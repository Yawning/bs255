// Copyright (c) 2024 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

package bs255

import (
	"crypto"
	"errors"
	"io"

	"github.com/gtank/ristretto255"
	"gitlab.com/yawning/tuplehash"
)

var (
	dsSignatureNonce     = []byte("bs255/v0:SignNonce")
	dsSignatureChallenge = []byte("bs255/v0:SignChallenge")

	errSelfVerifyFailure = errors.New("bs255: failed to self-verify signature")

	errInvalidSignature = errors.New("bs255: invalid signature")
	errInvalidR         = errors.New("bs255: invalid R")
	errIdentityR        = errors.New("bs255: R is identity element")
	errNonCanonicalS    = errors.New("bs255: non-canonical s")
	errRMismatch        = errors.New("bs255: Rcheck != R")

	defaultOptions SignatureOptions
)

// DeterministicSign is a [io.Reader] that can be passed to Sign to
// produce deterministic signatures.
var DeterministicSign = &deterministicSignatureReader{}

// SignatureOptions can be used with `PrivateKey.Sign` or `PublicKey.Verify`
// to configure various parameters.
type SignatureOptions struct {
	// DomainSeparator specifies the domain separator to be used
	// when signing or verifying a signature.  There is no practical
	// upper limit to the length.
	DomainSeparator string

	// SelfVerify will cause the signing process to verify the
	// signature after signing, to improve resilience against certain
	// fault attacks.
	//
	// WARNING: If this is set, signing will be significantly more
	// expensive.
	SelfVerify bool
}

// HashFunc returns `0`, and exists only to satisfy the [crypto/SignerOpts]
// interface.
func (opt *SignatureOptions) HashFunc() crypto.Hash {
	return 0
}

func getSignatureOptions(opts crypto.SignerOpts) *SignatureOptions {
	if o, ok := opts.(*SignatureOptions); ok {
		return o
	}
	return &defaultOptions
}

// Sign signs message with sk, using entropy from rng and options from opts,
// and returns a signature or error.  If no rng is provided, [crypto/rand.Reader]
// will be used.
func (sk *PrivateKey) Sign(rng io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	o := getSignatureOptions(opts)

	bytesP := sk.publicKey.elementBytes

	// Generate the per-signature nonce (k).
	//
	// This adopts a hedged approach of including:
	// - A per-private key static nonce (`prefix` in RFC 8032 Ed25519)
	// - Fresh entropy (`a` in BIP-0340)
	// - The signature domain separator.
	// - The public key (`bytes(P)` in BIP-0340)
	// - The message (`m` in BIP-0340, `M` in RFC 8032 Ed25519)
	//
	// In the deterministic case, `a` is the empty string.  Otherwise
	// it is 256-bits of entropy sampled from `rng`.
	xof := tuplehash.NewTupleHashXOF128(dsSignatureNonce)
	_, _ = xof.Write(sk.nonce)
	if err := writeAuxRand(xof, rng); err != nil {
		return nil, err
	}
	_, _ = xof.Write([]byte(o.DomainSeparator))
	_, _ = xof.Write(bytesP)
	_, _ = xof.Write(message)
	k, err := sampleNonZeroScalar(xof)
	if err != nil {
		return nil, err
	}

	// Let R = k*G.
	R := ristretto255.NewIdentityElement().ScalarBaseMult(k)
	bytesR := R.Bytes()

	// Compute the challenge scalar (e).
	e := computeChallenge(o.DomainSeparator, bytesR, bytesP, message)

	// Let sig = bytes(R) || bytes((k + ed) mod n).
	s := ristretto255.NewScalar().Multiply(e, sk.scalar)
	s.Add(s, k)

	sig := make([]byte, 0, SignatureSize)
	sig = append(sig, bytesR...)
	sig = append(sig, s.Bytes()...)

	if o.SelfVerify {
		// Verify the newly created signature.
		if !sk.PublicKey().Verify(message, sig, opts) {
			return nil, errSelfVerifyFailure
		}
	}

	return sig, nil
}

// Verify returns true iff sig is a valid signature over message by pk,
// with the options opts.
func (pk *PublicKey) Verify(message, sig []byte, opts crypto.SignerOpts) bool {
	return pk.doVerify(message, sig, opts) == nil
}

func (pk *PublicKey) doVerify(message, sig []byte, opts crypto.SignerOpts) error {
	o := getSignatureOptions(opts)

	if len(sig) != SignatureSize {
		return errInvalidSignature
	}

	bytesR, bytesS, bytesP := sig[0:32], sig[32:64], pk.elementBytes

	// Decode bytesR as a valid canonical encoding of a ristretto255
	// group element, that MUST NOT be the identity element.
	R, err := ristretto255.NewIdentityElement().SetCanonicalBytes(bytesR)
	if err != nil {
		return errInvalidR
	}
	if geIsIdentity(R) {
		return errIdentityR
	}

	// Decode bytesS as a canonicaly encoded ristretto255 scalar.
	s, err := ristretto255.NewScalar().SetCanonicalBytes(bytesS)
	if err != nil {
		return errNonCanonicalS
	}

	// Re-compute the challenge scalar (e).
	e := computeChallenge(o.DomainSeparator, bytesR, bytesP, message)

	// Let Rcheck = s*G - e*P.
	//
	// Note: No need to check if Rcheck is the identity element, since R
	// is guaranteed not to be, and the final verification will fail.
	eNeg := e.Negate(e)
	Rcheck := ristretto255.NewIdentityElement().VarTimeDoubleScalarBaseMult(eNeg, pk.element, s)

	if R.Equal(Rcheck) == 0 {
		return errRMismatch
	}

	return nil
}

func computeChallenge(domainSeparator string, bytesR []byte, bytesP []byte, message []byte) *ristretto255.Scalar {
	h := tuplehash.NewTupleHash128(dsSignatureChallenge, wideScalarSize)
	_, _ = h.Write([]byte(domainSeparator))
	_, _ = h.Write(bytesR)
	_, _ = h.Write(bytesP)
	_, _ = h.Write(message)

	sc, _ := ristretto255.NewScalar().SetUniformBytes(h.Sum(nil)) // Can't fail.
	return sc
}
