package plugin

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"filippo.io/age/plugin"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Agent keeps TPM identities usable after a single unlock. It caches the PIN
// per identity and the parent SRKs, so a key agreement only needs to load the
// key; the private key never leaves the TPM.
type Agent struct {
	tpm     transport.TPMCloser
	timeout time.Duration

	mu   sync.Mutex
	keys map[[32]byte]*agentKey
	// srks caches parent keys by name. Identities created on the same TPM
	// share one SRK, so this holds at most a handful of objects.
	srks map[string]*agentSRK
}

type agentKey struct {
	identity *Identity
	pin      []byte
	unlocked time.Time
}

type agentSRK struct {
	handle *tpm2.AuthHandle
	public *tpm2.TPMTPublic
}

// NewAgent returns an agent using tpm. A non-zero timeout drops cached PINs
// that long after they were unlocked.
func NewAgent(tpm transport.TPMCloser, timeout time.Duration) *Agent {
	return &Agent{tpm: tpm, timeout: timeout, keys: map[[32]byte]*agentKey{}, srks: map[string]*agentSRK{}}
}

// Serve accepts connections on l until it is closed.
func (a *Agent) Serve(l net.Listener) error {
	if a.timeout > 0 {
		t := time.NewTicker(min(a.timeout, time.Minute))
		defer t.Stop()
		go func() {
			for range t.C {
				a.mu.Lock()
				a.expire()
				a.mu.Unlock()
			}
		}()
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go a.serveConn(conn)
	}
}

func (a *Agent) serveConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if uc, ok := conn.(*net.UnixConn); ok {
		uid, err := peerUID(uc)
		if err != nil || uid != os.Getuid() {
			Log.Printf("agent: rejecting peer uid %d: %v", uid, err)
			return
		}
	}

	var rsp *agentResponse
	line, err := bufio.NewReader(io.LimitReader(conn, 64<<10)).ReadBytes('\n')
	if err != nil {
		rsp = errorResponse(AgentErrInvalid, "failed reading request")
	} else {
		var req agentRequest
		if err := json.Unmarshal(line, &req); err != nil {
			rsp = errorResponse(AgentErrInvalid, "malformed request")
		} else {
			rsp = a.handle(&req)
			clear(req.Password)
		}
	}
	b, _ := json.Marshal(rsp)
	conn.Write(append(b, '\n'))
}

func errorResponse(code, msg string) *agentResponse {
	return &agentResponse{Error: code, Message: msg}
}

// handle processes a single request.
func (a *Agent) handle(req *agentRequest) *agentResponse {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expire()

	switch req.Op {
	case "status":
		n := 0
		for _, k := range a.keys {
			if k.pin != nil {
				n++
			}
		}
		return &agentResponse{OK: true, Unlocked: &n}
	case "lock":
		a.lock()
		return &agentResponse{OK: true}
	case "unlock":
		k, err := a.key(req.Key)
		if err != nil {
			return errorResponse(AgentErrInvalid, err.Error())
		}
		if !k.identity.HasPIN() {
			return &agentResponse{OK: true}
		}
		// Verify the PIN with a key agreement against a random point.
		eph, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return errorResponse(AgentErrInternal, err.Error())
		}
		if _, err := a.ecdh(k, req.Password, eph.PublicKey()); err != nil {
			return tpmErrorResponse(err)
		}
		k.setPIN(req.Password)
		return &agentResponse{OK: true}
	case "ecdh":
		k, err := a.key(req.Key)
		if err != nil {
			return errorResponse(AgentErrInvalid, err.Error())
		}
		remote, err := ecdh.P256().NewPublicKey(req.Share)
		if err != nil {
			return errorResponse(AgentErrInvalid, "invalid share")
		}
		if k.identity.HasPIN() && k.pin == nil {
			return errorResponse(AgentErrLocked, "identity is locked")
		}
		secret, err := a.ecdh(k, k.pin, remote)
		if err != nil {
			if isAuthFailure(err) {
				// The cached PIN no longer works; forget it.
				k.clearPIN()
			}
			return tpmErrorResponse(err)
		}
		return &agentResponse{OK: true, Secret: secret}
	default:
		return errorResponse(AgentErrInvalid, "unknown op")
	}
}

func tpmErrorResponse(err error) *agentResponse {
	if isAuthFailure(err) {
		return errorResponse(AgentErrBadPassword, "incorrect PIN")
	}
	if errors.Is(err, tpm2.TPMRCLockout) {
		return errorResponse(AgentErrInternal, "TPM is in dictionary attack lockout")
	}
	return errorResponse(AgentErrInternal, err.Error())
}

func isAuthFailure(err error) bool {
	return errors.Is(err, tpm2.TPMRCAuthFail) || errors.Is(err, tpm2.TPMRCBadAuth)
}

// key returns the cache entry for the serialized identity b.
func (a *Agent) key(b []byte) (*agentKey, error) {
	id := sha256.Sum256(b)
	if k, ok := a.keys[id]; ok {
		return k, nil
	}
	identity, err := DecodeIdentity(plugin.EncodeIdentity(PluginName, b))
	if err != nil {
		return nil, fmt.Errorf("invalid identity: %v", err)
	}
	k := &agentKey{identity: identity}
	a.keys[id] = k
	return k, nil
}

// ecdh runs the key agreement with the identity's key, loading it under the
// cached SRK. If the TPM rejects the cached SRK it is recreated once.
func (a *Agent) ecdh(k *agentKey, pin []byte, remote *ecdh.PublicKey) ([]byte, error) {
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		var srk *agentSRK
		srk, err = a.srk(k.identity)
		if err != nil {
			return nil, err
		}
		var handle *tpm2.AuthHandle
		handle, err = LoadIdentityWithParent(a.tpm, *srk.handle, k.identity)
		if err == nil {
			handle.Auth = tpm2.PasswordAuth(pin)
			var secret []byte
			secret, err = ecdhZGen(a.tpm, srk.handle, srk.public, handle, remote)
			FlushHandle(a.tpm, handle)
			if err == nil || isAuthFailure(err) || errors.Is(err, tpm2.TPMRCLockout) {
				return secret, err
			}
		}
		Log.Printf("agent: key agreement failed, recreating SRK: %v", err)
		a.flushSRKs()
	}
	return nil, err
}

// srk returns the parent key for identity, creating and caching it if needed.
func (a *Agent) srk(identity *Identity) (*agentSRK, error) {
	if identity.SRKName != nil {
		if srk, ok := a.srks[string(identity.SRKName.Buffer)]; ok {
			return srk, nil
		}
	}
	handle, public, err := AcquireIdentitySRK(a.tpm, identity)
	if err != nil {
		return nil, err
	}
	srk := &agentSRK{handle, public}
	if old, ok := a.srks[string(handle.Name.Buffer)]; ok {
		// A version 1 identity (no SRK name) whose SRK is already cached.
		FlushHandle(a.tpm, handle)
		return old, nil
	}
	a.srks[string(handle.Name.Buffer)] = srk
	return srk, nil
}

func (a *Agent) flushSRKs() {
	for name, srk := range a.srks {
		// Flushing the persistent shared SRK fails harmlessly.
		FlushHandle(a.tpm, srk.handle)
		delete(a.srks, name)
	}
}

func (a *Agent) expire() {
	if a.timeout == 0 {
		return
	}
	for _, k := range a.keys {
		if k.pin != nil && time.Since(k.unlocked) > a.timeout {
			k.clearPIN()
		}
	}
}

func (a *Agent) lock() {
	for _, k := range a.keys {
		k.clearPIN()
	}
}

// Close forgets all PINs and flushes all loaded handles.
func (a *Agent) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, k := range a.keys {
		k.clearPIN()
		delete(a.keys, id)
	}
	a.flushSRKs()
}

func (k *agentKey) setPIN(pin []byte) {
	k.clearPIN()
	k.pin = make([]byte, len(pin))
	lockMemory(k.pin)
	copy(k.pin, pin)
	k.unlocked = time.Now()
}

func (k *agentKey) clearPIN() {
	if k.pin == nil {
		return
	}
	clear(k.pin)
	unlockMemory(k.pin)
	k.pin = nil
}

// AgentListener returns the listener for the agent: the systemd-activated
// socket if present, otherwise a new socket at path in a private directory.
// The returned cleanup function removes the socket.
func AgentListener(path string) (net.Listener, func(), error) {
	if os.Getenv("LISTEN_PID") == strconv.Itoa(os.Getpid()) && os.Getenv("LISTEN_FDS") == "1" {
		os.Unsetenv("LISTEN_PID")
		os.Unsetenv("LISTEN_FDS")
		os.Unsetenv("LISTEN_FDNAMES")
		l, err := net.FileListener(os.NewFile(3, "listen"))
		if err != nil {
			return nil, nil, fmt.Errorf("failed using activated socket: %v", err)
		}
		return l, func() {}, nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	if err := checkPrivateDir(dir); err != nil {
		return nil, nil, err
	}
	if NewAgentClient(path).Available() {
		return nil, nil, fmt.Errorf("an agent is already listening on %s", path)
	}
	os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, nil, err
	}
	return l, func() { l.Close(); os.Remove(path) }, nil
}
