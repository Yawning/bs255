// Copyright (c) 2024 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

package bs255

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/gtank/ristretto255"
	"gitlab.com/yawning/tuplehash"
)

const (
	wideScalarSize = 64
	maxRetries     = 3
)

var (
	scZero     = ristretto255.NewScalar()
	geIdentity = ristretto255.NewIdentityElement()

	errTooManyRetries = errors.New("bs255: too many rejection sampling retries")
)

func sampleNonZeroScalar(xof *tuplehash.Hasher) (*ristretto255.Scalar, error) {
	sc := ristretto255.NewScalar()

	var tmp [wideScalarSize]byte
	for i := 0; i < maxRetries; i++ {
		_, _ = xof.Read(tmp[:])
		_, _ = sc.SetUniformBytes(tmp[:]) // Can't fail.

		// This is the one and only edge case, which occurs when
		// sampling the signature nonce `k`.
		//
		// The probability of this occurring is cryptographically
		// insignificant, so implementations MAY choose to fail
		// instead (and in fact BIP-0340 specifies an abort when
		// signing if this happens).
		//
		// This implementation opts for rejection-sampling as XOFs
		// are pretty great, but in practical terms it is astronomically
		// unlikely that a decision here makes an actual difference,
		// and more importantly, has no impact on what is considered
		// a valid signature.
		//
		// In either case, this check MUST be done in constant time.
		if sc.Equal(scZero) == 0 {
			return sc, nil
		}
	}

	return nil, errTooManyRetries
}

func geIsIdentity(ge *ristretto255.Element) bool {
	return ge.Equal(geIdentity) == 1
}

func writeAuxRand(xof *tuplehash.Hasher, rng io.Reader) error {
	const auxRandSize = 32

	if rng == nil {
		rng = rand.Reader
	}

	// If the rng is explicitly `DeterministicSign`, write the
	// empty string as a tuple element.
	//
	// Supporting this is entirely optional, and implementors
	// MAY choose to do something entirely different, and this
	// too, does not impact what is considered a valid signature.
	if _, ok := rng.(*deterministicSignatureReader); ok {
		_, _ = xof.Write([]byte{})
		return nil
	}

	var tmp [auxRandSize]byte
	if _, err := rng.Read(tmp[:]); err != nil {
		return fmt.Errorf("%w: %w", errRngFailure, err)
	}
	_, _ = xof.Write(tmp[:])

	return nil
}

type deterministicSignatureReader struct{}

func (r *deterministicSignatureReader) Read(_ []byte) (int, error) {
	panic("bs255: DeterministicSign is not intended to be called")
}
