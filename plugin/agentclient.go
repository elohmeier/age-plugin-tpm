package plugin

import (
	"bufio"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	hpkeecdh "filippo.io/hpke/crypto/ecdh"
)

// Error codes returned by the agent, see AGENT.md.
const (
	AgentErrLocked      = "locked"
	AgentErrBadPassword = "bad-password"
	AgentErrInvalid     = "invalid"
	AgentErrInternal    = "internal"
)

var (
	ErrAgentLocked      = &AgentError{Code: AgentErrLocked}
	ErrAgentBadPassword = &AgentError{Code: AgentErrBadPassword}
)

// AgentError is an error reported by the agent.
type AgentError struct {
	Code    string
	Message string
}

func (e *AgentError) Error() string {
	if e.Message == "" {
		return "agent: " + e.Code
	}
	return fmt.Sprintf("agent: %s: %s", e.Code, e.Message)
}

// Is matches agent errors by code, so errors.Is(err, ErrAgentLocked) works.
func (e *AgentError) Is(target error) bool {
	t, ok := target.(*AgentError)
	return ok && t.Code == e.Code
}

type agentRequest struct {
	Op       string `json:"op"`
	Key      []byte `json:"key,omitempty"`
	Password []byte `json:"password,omitempty"`
	Share    []byte `json:"share,omitempty"`
}

type agentResponse struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Message  string `json:"message,omitempty"`
	Secret   []byte `json:"secret,omitempty"`
	Unlocked *int   `json:"unlocked,omitempty"`
}

// DefaultAgentSocket returns the agent socket path:
// $AGE_PLUGIN_TPM_AGENT_SOCK, else $XDG_RUNTIME_DIR/age-plugin-tpm/agent.sock.
func DefaultAgentSocket() string {
	if s := os.Getenv("AGE_PLUGIN_TPM_AGENT_SOCK"); s != "" {
		return s
	}
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), fmt.Sprintf("age-plugin-tpm-%d", os.Getuid()))
		return filepath.Join(dir, "agent.sock")
	}
	return filepath.Join(dir, "age-plugin-tpm", "agent.sock")
}

// AgentClient talks to the unlock agent.
type AgentClient struct {
	Path string
}

func NewAgentClient(path string) *AgentClient {
	return &AgentClient{Path: path}
}

// Available reports whether the agent socket accepts connections.
func (c *AgentClient) Available() bool {
	conn, err := c.dial()
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// dial connects to the agent after checking that the socket directory is
// private, so PINs are never handed to a socket planted by another user.
func (c *AgentClient) dial() (net.Conn, error) {
	if err := checkPrivateDir(filepath.Dir(c.Path)); err != nil {
		return nil, err
	}
	return net.DialTimeout("unix", c.Path, time.Second)
}

func (c *AgentClient) do(req *agentRequest) (*agentResponse, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, fmt.Errorf("failed connecting to agent: %w", err)
	}
	defer conn.Close()

	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return nil, fmt.Errorf("failed writing to agent: %w", err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("failed reading from agent: %w", err)
	}
	var rsp agentResponse
	if err := json.Unmarshal(line, &rsp); err != nil {
		return nil, fmt.Errorf("invalid agent response: %w", err)
	}
	if !rsp.OK {
		return nil, &AgentError{Code: rsp.Error, Message: rsp.Message}
	}
	return &rsp, nil
}

// ECDH asks the agent for the P-256 shared secret between the identity and
// the uncompressed point share.
func (c *AgentClient) ECDH(identity *Identity, share []byte) ([]byte, error) {
	rsp, err := c.do(&agentRequest{Op: "ecdh", Key: identity.Bytes(), Share: share})
	if err != nil {
		return nil, err
	}
	return rsp.Secret, nil
}

// Unlock hands the PIN for identity to the agent, which verifies and caches it.
func (c *AgentClient) Unlock(identity *Identity, pin []byte) error {
	_, err := c.do(&agentRequest{Op: "unlock", Key: identity.Bytes(), Password: pin})
	return err
}

// Lock makes the agent forget all cached PINs.
func (c *AgentClient) Lock() error {
	_, err := c.do(&agentRequest{Op: "lock"})
	return err
}

// Status returns the number of unlocked identities.
func (c *AgentClient) Status() (int, error) {
	rsp, err := c.do(&agentRequest{Op: "status"})
	if err != nil {
		return 0, err
	}
	if rsp.Unlocked == nil {
		return 0, nil
	}
	return *rsp.Unlocked, nil
}

// AgentKeyExchange performs the key agreement through the agent, unlocking
// the identity with a PIN from the pin callback when the agent reports it as
// locked.
type AgentKeyExchange struct {
	agent *AgentClient
	i     *Identity
	pin   func() ([]byte, error)
}

var _ hpkeecdh.KeyExchanger = &AgentKeyExchange{}

func NewAgentKeyExchange(agent *AgentClient, i *Identity, pin func() ([]byte, error)) *AgentKeyExchange {
	return &AgentKeyExchange{agent, i, pin}
}

func (a *AgentKeyExchange) PublicKey() *ecdh.PublicKey {
	return a.i.Publickey()
}

func (a *AgentKeyExchange) Curve() ecdh.Curve {
	return ecdh.P256()
}

// Maximum PIN prompts per key agreement. Each wrong PIN counts towards the
// TPM dictionary attack lockout.
const maxPINAttempts = 2

func (a *AgentKeyExchange) ECDH(remoteKey *ecdh.PublicKey) ([]byte, error) {
	share := remoteKey.Bytes()
	secret, err := a.agent.ECDH(a.i, share)
	if !errors.Is(err, ErrAgentLocked) {
		return secret, err
	}
	for attempt := 1; ; attempt++ {
		pin, err := a.pin()
		if err != nil {
			return nil, fmt.Errorf("failed to get pin: %v", err)
		}
		err = a.agent.Unlock(a.i, pin)
		if err == nil {
			break
		}
		// A PIN from the environment won't change, so don't burn another attempt.
		if errors.Is(err, ErrAgentBadPassword) && attempt < maxPINAttempts && os.Getenv("AGE_TPM_PIN") == "" {
			continue
		}
		return nil, err
	}
	return a.agent.ECDH(a.i, share)
}
