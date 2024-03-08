// Copyright (c) 2024 Yawning Angel
//
// SPDX-License-Identifier: BSD-3-Clause

package bs255

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	testDomainSep = "bs255-tests"
	testMessage   = "Liberty is meaningless if it is only the liberty to agree with those in power."
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

	t.Run("Integration", func(t *testing.T) {
		signer := crypto.Signer(sk)

		sig, err := signer.Sign(rand.Reader, msgBytes, nil)
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
