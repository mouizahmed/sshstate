package sshkeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

const MinRSABits = 2048

var ErrPassphraseRequired = errors.New("source key is passphrase protected")

type Key struct {
	PrivateKey  string
	PublicKey   string
	Fingerprint string
	Algorithm   string
	Comment     string
}

func Import(raw, passphrase []byte, comment string) (*Key, error) {
	priv, err := parse(raw, passphrase)
	if err != nil {
		return nil, err
	}
	if err := checkStrength(priv); err != nil {
		return nil, err
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("unsupported key type: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, fmt.Errorf("normalize private key: %w", err)
	}

	pub := signer.PublicKey()
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if comment != "" {
		line += " " + comment
	}
	return &Key{
		PrivateKey:  string(pem.EncodeToMemory(block)),
		PublicKey:   line,
		Fingerprint: ssh.FingerprintSHA256(pub),
		Algorithm:   pub.Type(),
		Comment:     comment,
	}, nil
}

func parse(raw, passphrase []byte) (any, error) {
	if len(passphrase) > 0 {
		priv, err := ssh.ParseRawPrivateKeyWithPassphrase(raw, passphrase)
		if err != nil {
			if errors.Is(err, x509.IncorrectPasswordError) {
				return nil, errors.New("incorrect passphrase for source key")
			}
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return priv, nil
	}
	priv, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, ErrPassphraseRequired
		}
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return priv, nil
}

func checkStrength(priv any) error {
	switch k := priv.(type) {
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		return nil
	case *rsa.PrivateKey:
		if bits := k.N.BitLen(); bits < MinRSABits {
			return fmt.Errorf("RSA key is %d bits; v1 requires at least %d", bits, MinRSABits)
		}
		return nil
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		}
		return fmt.Errorf("ECDSA curve %s is not a standard NIST curve supported in v1", k.Curve.Params().Name)
	default:
		return fmt.Errorf("key type %T is not supported in v1 (Ed25519, RSA >= %d, and NIST ECDSA are)", priv, MinRSABits)
	}
}

func Signer(privateKey string) (ssh.Signer, error) {
	s, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		return nil, fmt.Errorf("load stored private key: %w", err)
	}
	return s, nil
}

func PublicKeyFingerprint(authorizedKey string) (string, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}
	return ssh.FingerprintSHA256(pub), nil
}

func PublicKeyDigest(authorizedKey string) (string, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "", fmt.Errorf("parse public key: %w", err)
	}
	return fingerprintHex(pub), nil
}
