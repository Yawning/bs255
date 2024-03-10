// Copyright (c) 2024 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

package bs255

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/stretchr/testify/require"
)

const (
	testDomainSep = "bs255-tests"
	testMessage   = "Liberty is meaningless if it is only the liberty to agree with those in power."

	invalidGeHex = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
)

func TestKey(t *testing.T) {
	t.Run("PrivateKey", func(t *testing.T) {
		sk, err := GenerateKey()
		require.NotNil(t, sk, "GenerateKey: rval")
		require.NoError(t, err, "GenerateKey")

		skBytes := sk.Bytes()
		sk2, err := NewPrivateKey(skBytes)
		require.NotNil(t, sk2, "NewPrivateKey: rval")
		require.NoError(t, err, "NewPrivateKey")

		require.EqualValues(t, skBytes, sk2.Bytes(), "Bytes(): should be skBytes")
		require.True(t, sk.Equal(sk2), "Equal(): sk should equal sk2")
	})
	t.Run("PublicKey", func(t *testing.T) {
		sk, _ := GenerateKey()
		pk := sk.PublicKey()
		pkBytes := pk.Bytes()

		pk2, err := NewPublicKey(pkBytes)
		require.NotNil(t, pk2, "NewPublicKey: rval")
		require.NoError(t, err, "NewPublicKey")

		require.EqualValues(t, pkBytes, pk2.Bytes(), "Bytes(): should be pkBytes")
		require.True(t, pk.Equal(pk2), "Equal(): pk should equal pk2")

		pk3, err := NewPublicKey(mustUnhex(t, invalidGeHex))
		require.Nil(t, pk3, "NewPublicKey: invalid group element")
		require.ErrorIs(t, err, errInvalidPublicKey, "NewPublicKey")

		pk3, err = NewPublicKey(ristretto255.NewIdentityElement().Bytes())
		require.Nil(t, pk3, "NewPublicKey: identity")
		require.ErrorIs(t, err, errAIsIdentity, "NewPublicKey")
	})
}

func TestDH(t *testing.T) {
	alicePriv, err := GenerateKey()
	require.NoError(t, err, "GenerateKey: Alice")
	alicePubBytes := alicePriv.PublicKey().Bytes()

	bobPriv, err := GenerateKey()
	require.NoError(t, err, "GenerateKey: Bob")
	bobPubBytes := bobPriv.PublicKey().Bytes()

	bobPub, err := NewPublicKey(bobPubBytes)
	require.NoError(t, err, "NewPublicKey: Bob")

	alicePub, err := NewPublicKey(alicePubBytes)
	require.NoError(t, err, "NewPublicKey: Alice")

	aliceShared, err := alicePriv.DH(testDomainSep, bobPub)
	require.NoError(t, err, "DH: Alice")

	bobShared, err := bobPriv.DH(testDomainSep, alicePub)
	require.NoError(t, err, "DH: Bob")

	require.EqualValues(t, aliceShared, bobShared, "shared secrets should match")
}

func TestSignature(t *testing.T) {
	sk, err := GenerateKey()
	require.NotNil(t, sk, "GenerateKey: rval")
	require.NoError(t, err, "GenerateKey")

	pk := sk.PublicKey()

	msgBytes := []byte(testMessage)

	scOne := make([]byte, 32)
	scOne[0] = 0x1

	t.Run("Integration", func(t *testing.T) {
		signer := crypto.Signer(sk)

		sig, err := signer.Sign(rand.Reader, msgBytes, &SignatureOptions{
			SelfVerify: true,
		})
		require.NoError(t, err, "Sign")

		ok := pk.Verify(msgBytes, sig, nil)
		require.True(t, ok, "Verify")

		tmp := bytes.Clone(msgBytes)
		tmp[0] ^= 0x69
		ok = pk.Verify(tmp, sig, nil)
		require.False(t, ok, "Verify: Corrupted msg")

		ok = pk.Verify(msgBytes[:5], sig, nil)
		require.False(t, ok, "Verify: Truncated h")
	})
	t.Run("Sign", func(t *testing.T) {
		t.Run("NonDeterministic", func(t *testing.T) {
			signer := crypto.Signer(sk)

			sig, err := signer.Sign(nil, msgBytes, nil)
			require.NoError(t, err, "Sign")

			sig2, err := signer.Sign(nil, msgBytes, nil)
			require.NoError(t, err, "Sign: Again")

			require.NotEqualValues(t, sig[:32], sig2[:32], "R should be different")
			require.NotEqualValues(t, sig[32:], sig2[32:], "s should be different")
		})
		t.Run("Deterministic", func(t *testing.T) {
			signer := crypto.Signer(sk)

			sig, err := signer.Sign(DeterministicSign, msgBytes, nil)
			require.NoError(t, err, "Sign")

			sig2, err := signer.Sign(DeterministicSign, msgBytes, nil)
			require.NoError(t, err, "Sign: Again")
			require.EqualValues(t, sig, sig2, "signatures should be match")

			sig2, err = signer.Sign(DeterministicSign, msgBytes, &SignatureOptions{
				DomainSeparator: testDomainSep,
			})
			require.NoError(t, err, "Sign: Domain sep")
			require.NotEqualValues(t, sig[:32], sig2[:32], "R should be different")

			sig2, err = signer.Sign(DeterministicSign, []byte("Different message"), nil)
			require.NoError(t, err, "Sign: Message")
			require.NotEqualValues(t, sig[:32], sig2[:32], "R should be different")
		})
	})
	t.Run("Verify/Invalid", func(t *testing.T) {
		t.Run("Size", func(t *testing.T) {
			var shortSig [SignatureSize - 1]byte

			err := pk.doVerify(msgBytes, shortSig[:], nil)
			require.ErrorIs(t, err, errInvalidSignature)
		})
		t.Run("NonCanonicalR", func(t *testing.T) {
			badRSig := mustUnhex(t, invalidGeHex)
			badRSig = append(badRSig, scOne...)

			err := pk.doVerify(msgBytes, badRSig, nil)
			require.ErrorIs(t, err, errInvalidR)
		})
		t.Run("IdentityR", func(t *testing.T) {
			identityRSig := append(ristretto255.NewIdentityElement().Bytes(), scOne...)

			err := pk.doVerify(msgBytes, identityRSig, nil)
			require.ErrorIs(t, err, errIdentityR)
		})
		t.Run("NonCanonicalS", func(t *testing.T) {
			bytesBadS := mustUnhex(t, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
			badSSig := append(ristretto255.NewGeneratorElement().Bytes(), bytesBadS...)

			err := pk.doVerify(msgBytes, badSSig, nil)
			require.ErrorIs(t, err, errNonCanonicalS)
		})
	})
}

func BenchmarkBs255(b *testing.B) {
	randomPriv, err := GenerateKey()
	require.NoError(b, err)
	randomPrivBytes := randomPriv.Bytes()

	randomPriv2, err := GenerateKey()
	require.NoError(b, err)
	randomPub := randomPriv2.PublicKey()

	msgBytes := []byte(testMessage)

	randomSig, err := randomPriv2.Sign(rand.Reader, msgBytes, nil)
	require.NoError(b, err)

	b.Run("GenerateKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := GenerateKey()
			require.NoError(b, err)
		}
	})
	b.Run("NewPrivateKey", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := NewPrivateKey(randomPrivBytes)
			require.NoError(b, err)
		}
	})
	b.Run("PrivateKey", func(b *testing.B) {
		b.Run("Bytes", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = randomPriv.Bytes()
			}
		})
		b.Run("DH", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = randomPriv.DH(testDomainSep, randomPub)
			}
		})
		b.Run("Sign", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = randomPriv.Sign(rand.Reader, msgBytes, nil)
			}
		})
		b.Run("Sign/Paranoid", func(b *testing.B) {
			opts := &SignatureOptions{
				SelfVerify: true,
			}
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = randomPriv.Sign(rand.Reader, msgBytes, opts)
			}
		})
	})
	b.Run("PublicKey", func(b *testing.B) {
		b.Run("Bytes", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = randomPub.Bytes()
			}
		})
		b.Run("Verify", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				ok := randomPub.Verify(msgBytes, randomSig, nil)
				require.True(b, ok)
			}
		})
	})
}

func mustUnhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	require.NoError(t, err, "hex.DecodeString")
	return b
}
