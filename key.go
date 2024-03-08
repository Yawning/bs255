// Copyright (c) 2024 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

// Package bs255 implements the bs255 Schnorr signature scheme.
package bs255

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/gtank/ristretto255"
	"gitlab.com/yawning/tuplehash"
)

const (
	// PrivateKeySize is the size of a private key, in bytes.
	PrivateKeySize = 32
	// PublicKeySize is the size of a public key, in bytes.
	PublicKeySize = 32
	// SignatureSize is the size of a signature, in bytes.
	SignatureSize = 64
)

var (
	errInvalidPrivateKey = errors.New("bs255: invalid private key")
	errInvalidPublicKey  = errors.New("bs255: invalid public key")
	errRngFailure        = errors.New("bs255: entropy source failure")
	errAIsIdentity       = errors.New("bs255: public key is identity element")

	dsExpandPrivateKey = []byte("bs255/v0:ExpandPrivateKey")
	dsDiffieHellman    = []byte("bs255/v0:DiffieHellman")
)

// PrivateKey is a bs255 private key.
type PrivateKey struct {
	rawBytes []byte

	scalar *ristretto255.Scalar // INVARIANT: Always [1, n)
	nonce  []byte

	publicKey *PublicKey
}

// DH performs a Diffie-Hellman exchange and returns the shared secret.
// The resulting group operation is never the identity element, and element
// is passed through a PRF with the provided domain separator prior to
// being returned.
func (sk *PrivateKey) DH(domainSep string, remote *PublicKey) ([]byte, error) {
	ge := ristretto255.NewIdentityElement().ScalarMult(sk.scalar, remote.element)

	h := tuplehash.NewTupleHash128(dsDiffieHellman, PublicKeySize)
	_, _ = h.Write([]byte(domainSep))
	_, _ = h.Write(ge.Bytes())
	return h.Sum(nil), nil
}

// Equal returns whether `x` represents the same private key as `sk`.
// This check is performed in constant time as long as the key types
// match.
func (sk *PrivateKey) Equal(x crypto.PrivateKey) bool {
	other, ok := x.(*PrivateKey)
	if !ok {
		return false
	}

	if sk.rawBytes == nil || other.rawBytes == nil {
		panic(errInvalidPrivateKey)
	}

	// The derivation scheme is deterministic, so just compare the raw bytes.
	return subtle.ConstantTimeCompare(sk.rawBytes, other.rawBytes) == 1
}

// PublicKey returns the public key corresponding to `k`.
func (sk *PrivateKey) PublicKey() *PublicKey {
	return sk.publicKey
}

// Public returns the [crypto.PublicKey] corresponding to `k`.
func (sk *PrivateKey) Public() crypto.PublicKey {
	return sk.publicKey
}

// Bytes returns a copy of the byte-encoding of the private key.
func (sk *PrivateKey) Bytes() []byte {
	if sk.rawBytes == nil {
		panic(errInvalidPrivateKey)
	}
	return bytes.Clone(sk.rawBytes)
}

// NewPrivateKey checks that `key` is valid and returns the corresponding
// PrivateKey.
//
// This routine will only fail if key is not `PrivateKeySize`-bytes long,
// and will never generate a private key with a public key that is the
// identity element.
func NewPrivateKey(key []byte) (*PrivateKey, error) {
	if len(key) != PrivateKeySize {
		return nil, errInvalidPrivateKey
	}

	const nonceSize = 32

	sk := &PrivateKey{
		rawBytes: bytes.Clone(key),
		scalar:   nil,
		nonce:    make([]byte, nonceSize),
	}

	xof := tuplehash.NewTupleHashXOF128(dsExpandPrivateKey)
	_, _ = xof.Write(key)
	_, _ = xof.Read(sk.nonce)
	sk.scalar = sampleNonZeroScalar(xof)

	var err error
	ge := ristretto255.NewIdentityElement().ScalarBaseMult(sk.scalar)
	if sk.publicKey, err = newPublicKeyFromElement(ge); err != nil {
		// NEVER: error only returned on ge == inf.
		panic("bs255: failed to generate public key: " + err.Error())
	}

	return sk, nil
}

// GenerateKey generates a new PrivateKey, using [crypto/rand.Reader]
// as the entropy source.
func GenerateKey() (*PrivateKey, error) {
	var raw [PrivateKeySize]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, fmt.Errorf("%w: %w", errRngFailure, err)
	}

	return NewPrivateKey(raw[:])
}

// PublicKey is a bs255 public key.
type PublicKey struct {
	element      *ristretto255.Element
	elementBytes []byte
}

// Bytes returns a copy of the byte-encoding of the public key.
func (pk *PublicKey) Bytes() []byte {
	if pk.elementBytes == nil {
		panic(errInvalidPublicKey)
	}
	return bytes.Clone(pk.elementBytes)
}

// Equal returns whether `x` represents the same public key as `k`.
// This check is performed in constant time as long as the key types
// match.
func (pk *PublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*PublicKey)
	if !ok {
		return false
	}

	if pk.elementBytes == nil || other.elementBytes == nil {
		panic(errInvalidPublicKey)
	}

	// Comparing the serialized form is faster than comparing elements,
	// as we cache the serialized form.
	return subtle.ConstantTimeCompare(pk.elementBytes, other.elementBytes) == 1
}

// NewPublicKey checks that `key` is valid and returns a PublicKey.
//
// `key` MUST be a canonical encoding of a ristretto25519 group element,
// and MUST NOT be the identity element.
func NewPublicKey(key []byte) (*PublicKey, error) {
	ge, err := ristretto255.NewIdentityElement().SetCanonicalBytes(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidPublicKey, err)
	}

	return newPublicKeyFromElement(ge)
}

func newPublicKeyFromElement(ge *ristretto255.Element) (*PublicKey, error) {
	if geIsIdentity(ge) {
		return nil, errAIsIdentity
	}

	return &PublicKey{
		element:      ge,
		elementBytes: ge.Bytes(),
	}, nil
}
