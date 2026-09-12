// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only

package agentsrv

import (
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/mouizahmed/sshstate/internal/protocol"
	"github.com/mouizahmed/sshstate/internal/sshkeys"
	"github.com/mouizahmed/sshstate/internal/vault"
)

var errRefused = errors.New("this agent does not accept key management over the agent protocol")

var errLocked = errors.New("vault is locked")

type Agent struct {
	mgr *vault.Manager

	mu     sync.Mutex
	signer map[protocol.ID]ssh.Signer
}

func New(mgr *vault.Manager) *Agent {
	return &Agent{mgr: mgr, signer: map[protocol.ID]ssh.Signer{}}
}

func (a *Agent) Forget() {
	a.mu.Lock()
	defer a.mu.Unlock()
	clear(a.signer)
}

func (a *Agent) List() ([]*agent.Key, error) {
	views, err := a.mgr.Keys()
	if err != nil {
		if errors.Is(err, vault.ErrLocked) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]*agent.Key, 0, len(views))
	for _, v := range views {
		pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(v.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", v.RecordID, err)
		}
		if comment == "" {
			comment = v.Comment
		}
		out = append(out, &agent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: comment,
		})
	}
	return out, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	signer, err := a.signerFor(key)
	if err != nil {
		return nil, err
	}

	var sig *ssh.Signature
	if flags == 0 {
		sig, err = signer.Sign(nil, data)
	} else {
		algo, algoErr := algorithmFor(flags)
		if algoErr != nil {
			return nil, algoErr
		}
		as, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			return nil, fmt.Errorf("key type %s does not support %s", key.Type(), algo)
		}
		sig, err = as.SignWithAlgorithm(nil, data, algo)
	}
	if err != nil {
		return nil, err
	}
	a.mgr.Touch()
	return sig, nil
}

func algorithmFor(flags agent.SignatureFlags) (string, error) {
	switch {
	case flags&agent.SignatureFlagRsaSha512 != 0:
		return ssh.KeyAlgoRSASHA512, nil
	case flags&agent.SignatureFlagRsaSha256 != 0:
		return ssh.KeyAlgoRSASHA256, nil
	default:
		return "", fmt.Errorf("unsupported signature flags %d", flags)
	}
}

func (a *Agent) signerFor(key ssh.PublicKey) (ssh.Signer, error) {
	views, err := a.mgr.Keys()
	if err != nil {
		if errors.Is(err, vault.ErrLocked) {
			return nil, errLocked
		}
		return nil, err
	}
	want := string(key.Marshal())
	for _, v := range views {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(v.PublicKey))
		if err != nil {
			continue
		}
		if string(pub.Marshal()) != want {
			continue
		}
		return a.loadSigner(v.RecordID)
	}
	return nil, errors.New("no such identity")
}

func (a *Agent) loadSigner(id protocol.ID) (ssh.Signer, error) {
	a.mu.Lock()
	cached, ok := a.signer[id]
	a.mu.Unlock()
	if ok {
		return cached, nil
	}
	priv, err := a.mgr.PrivateKey(id)
	if err != nil {
		if errors.Is(err, vault.ErrLocked) {
			return nil, errLocked
		}
		return nil, err
	}
	signer, err := sshkeys.Signer(priv)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.signer[id] = signer
	a.mu.Unlock()
	return signer, nil
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	views, err := a.mgr.Keys()
	if err != nil {
		if errors.Is(err, vault.ErrLocked) {
			return nil, errLocked
		}
		return nil, err
	}
	out := make([]ssh.Signer, 0, len(views))
	for _, v := range views {
		s, err := a.loadSigner(v.RecordID)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (a *Agent) Add(agent.AddedKey) error   { return errRefused }
func (a *Agent) Remove(ssh.PublicKey) error { return errRefused }
func (a *Agent) RemoveAll() error           { return errRefused }

func (a *Agent) Lock([]byte) error   { return errRefused }
func (a *Agent) Unlock([]byte) error { return errRefused }

func (a *Agent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
