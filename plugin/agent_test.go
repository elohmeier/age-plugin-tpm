package plugin

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func startAgent(t *testing.T, tpm transport.TPMCloser, timeout time.Duration) *AgentClient {
	t.Helper()
	SetLogger(io.Discard)
	// Keep the path short; unix socket paths are limited to ~104 bytes.
	dir, err := os.MkdirTemp("", "agt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s", "agent.sock")

	l, cleanup, err := AgentListener(path)
	if err != nil {
		t.Fatalf("failed listening: %v", err)
	}
	agent := NewAgent(tpm, timeout)
	go agent.Serve(l)
	t.Cleanup(func() {
		cleanup()
		agent.Close()
	})
	return NewAgentClient(path)
}

// agentIdentity returns a copy of identity that unwraps through the agent.
func agentIdentity(t *testing.T, identity *Identity, client *AgentClient, pin func() ([]byte, error)) *Identity {
	t.Helper()
	i, err := DecodeIdentity(identity.String())
	if err != nil {
		t.Fatal(err)
	}
	i.Callbacks(nil, nil, pin)
	i.UseAgent(client)
	return i
}

// resetDictionaryAttackLockout sends TPM2_DictionaryAttackLockReset with an
// empty lockout password, which go-tpm has no command type for.
func resetDictionaryAttackLockout(t *testing.T, tpm transport.TPM) {
	t.Helper()
	cmd := []byte{
		0x80, 0x02, // TPM_ST_SESSIONS
		0x00, 0x00, 0x00, 0x1b, // command size
		0x00, 0x00, 0x01, 0x39, // TPM_CC_DictionaryAttackLockReset
		0x40, 0x00, 0x00, 0x0a, // TPM_RH_LOCKOUT
		0x00, 0x00, 0x00, 0x09, // authorization size
		0x40, 0x00, 0x00, 0x09, // TPM_RS_PW
		0x00, 0x00, // nonce
		0x00,       // session attributes
		0x00, 0x00, // empty password
	}
	rsp, err := tpm.Send(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if len(rsp) < 10 || !bytes.Equal(rsp[6:10], []byte{0, 0, 0, 0}) {
		t.Fatalf("lockout reset failed: %x", rsp)
	}
}

func randomShare(t *testing.T) []byte {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

func TestAgentPIN(t *testing.T) {
	SetLogger(io.Discard)
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed opening tpm: %v", err)
	}
	t.Cleanup(func() { tpm.Close() })

	pin := []byte("123456")
	identity, recipient, err := CreateIdentity(tpm, pin)
	if err != nil {
		t.Fatal(err)
	}
	client := startAgent(t, tpm, 0)

	if !client.Available() {
		t.Fatal("agent not available")
	}
	if _, err := client.ECDH(identity, randomShare(t)); !errors.Is(err, ErrAgentLocked) {
		t.Fatalf("expected locked, got %v", err)
	}
	if err := client.Unlock(identity, []byte("wrong")); !errors.Is(err, ErrAgentBadPassword) {
		t.Fatalf("expected bad-password, got %v", err)
	}
	if err := client.Unlock(identity, pin); err != nil {
		t.Fatalf("unlock failed: %v", err)
	}
	if n, err := client.Status(); err != nil || n != 1 {
		t.Fatalf("expected 1 unlocked identity, got %d, %v", n, err)
	}

	fileKey := []byte("0123456789abcdef")
	noPIN := func() ([]byte, error) {
		t.Fatal("unexpected PIN prompt")
		return nil, nil
	}

	t.Run("p256tag", func(t *testing.T) {
		stanzas, err := recipient.Wrap(fileKey)
		if err != nil {
			t.Fatal(err)
		}
		got, err := agentIdentity(t, identity, client, noPIN).Unwrap(stanzas)
		if err != nil {
			t.Fatalf("unwrap failed: %v", err)
		}
		if !bytes.Equal(got, fileKey) {
			t.Fatal("file keys differ")
		}
	})

	t.Run("tpm-ecc", func(t *testing.T) {
		stanzas, err := identity.TPMRecipient().Wrap(fileKey)
		if err != nil {
			t.Fatal(err)
		}
		got, err := agentIdentity(t, identity, client, noPIN).Unwrap(stanzas)
		if err != nil {
			t.Fatalf("unwrap failed: %v", err)
		}
		if !bytes.Equal(got, fileKey) {
			t.Fatal("file keys differ")
		}
	})

	if err := client.Lock(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ECDH(identity, randomShare(t)); !errors.Is(err, ErrAgentLocked) {
		t.Fatalf("expected locked after lock, got %v", err)
	}

	t.Run("unlock on demand", func(t *testing.T) {
		stanzas, err := recipient.Wrap(fileKey)
		if err != nil {
			t.Fatal(err)
		}
		prompts := 0
		i := agentIdentity(t, identity, client, func() ([]byte, error) {
			prompts++
			if prompts == 1 {
				return []byte("wrong"), nil
			}
			return pin, nil
		})
		got, err := i.Unwrap(stanzas)
		if err != nil {
			t.Fatalf("unwrap failed: %v", err)
		}
		if !bytes.Equal(got, fileKey) || prompts != 2 {
			t.Fatalf("unexpected result: %d prompts", prompts)
		}
	})

	t.Run("gives up after two wrong PINs", func(t *testing.T) {
		// The wrong PINs so far count towards the dictionary attack lockout.
		resetDictionaryAttackLockout(t, tpm)
		client.Lock()
		stanzas, err := recipient.Wrap(fileKey)
		if err != nil {
			t.Fatal(err)
		}
		prompts := 0
		i := agentIdentity(t, identity, client, func() ([]byte, error) {
			prompts++
			return []byte("wrong"), nil
		})
		if _, err := i.Unwrap(stanzas); !errors.Is(err, ErrAgentBadPassword) {
			t.Fatalf("expected bad-password, got %v", err)
		}
		if prompts != maxPINAttempts {
			t.Fatalf("expected %d prompts, got %d", maxPINAttempts, prompts)
		}
	})
}

func TestAgentNoPIN(t *testing.T) {
	SetLogger(io.Discard)
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed opening tpm: %v", err)
	}
	t.Cleanup(func() { tpm.Close() })

	identity, recipient, err := CreateIdentity(tpm, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := startAgent(t, tpm, 0)

	fileKey := []byte("0123456789abcdef")
	stanzas, err := recipient.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	i := agentIdentity(t, identity, client, func() ([]byte, error) {
		t.Fatal("unexpected PIN prompt")
		return nil, nil
	})
	got, err := i.Unwrap(stanzas)
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}
	if !bytes.Equal(got, fileKey) {
		t.Fatal("file keys differ")
	}

	// Stanzas for other keys are not ours.
	other, otherRecipient, err := CreateIdentity(tpm, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = other
	stanzas, err = otherRecipient.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.Unwrap(stanzas); !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Fatalf("expected incorrect identity, got %v", err)
	}
}

func TestAgentTimeout(t *testing.T) {
	SetLogger(io.Discard)
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed opening tpm: %v", err)
	}
	t.Cleanup(func() { tpm.Close() })

	pin := []byte("123456")
	identity, _, err := CreateIdentity(tpm, pin)
	if err != nil {
		t.Fatal(err)
	}
	client := startAgent(t, tpm, 50*time.Millisecond)

	if err := client.Unlock(identity, pin); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := client.ECDH(identity, randomShare(t)); !errors.Is(err, ErrAgentLocked) {
		t.Fatalf("expected locked after timeout, got %v", err)
	}
}

func TestAgentInvalidRequests(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed opening tpm: %v", err)
	}
	t.Cleanup(func() { tpm.Close() })

	SetLogger(io.Discard)
	agent := NewAgent(tpm, 0)
	defer agent.Close()
	for _, req := range []*agentRequest{
		{Op: "bogus"},
		{Op: "ecdh", Key: []byte("garbage"), Share: randomShare(t)},
		{Op: "unlock", Key: []byte("garbage")},
	} {
		if rsp := agent.handle(req); rsp.OK || rsp.Error != AgentErrInvalid {
			t.Fatalf("%s: expected invalid, got %+v", req.Op, rsp)
		}
	}
}

func TestAgentRejectsSharedDirectory(t *testing.T) {
	dir, err := os.MkdirTemp("", "agt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AgentListener(filepath.Join(dir, "agent.sock")); err == nil {
		t.Fatal("expected error for world-writable socket directory")
	}
	if NewAgentClient(filepath.Join(dir, "agent.sock")).Available() {
		t.Fatal("client must not use a world-writable socket directory")
	}
}
