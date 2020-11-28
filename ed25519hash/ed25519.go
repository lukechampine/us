// Package ed25519hash provides optimized routines for signing and verifying Sia
// hashes.
package ed25519hash

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"strconv"

	"filippo.io/edwards25519"
	"gitlab.com/NebulousLabs/Sia/crypto"
)

// Verify reports whether sig is a valid signature of hash by pub.
func Verify(pub ed25519.PublicKey, hash crypto.Hash, sig []byte) bool {
	if l := len(pub); l != ed25519.PublicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	if len(sig) != ed25519.SignatureSize || sig[63]&224 != 0 {
		return false
	}

	A, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return false
	}
	A.Negate(A)

	buf := make([]byte, 96)
	copy(buf[:32], sig[:32])
	copy(buf[32:], pub)
	copy(buf[64:], hash[:])
	hramDigest := sha512.Sum512(buf)
	hramDigestReduced := new(edwards25519.Scalar).SetUniformBytes(hramDigest[:])

	b, err := new(edwards25519.Scalar).SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}

	encodedR := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(hramDigestReduced, A, b).Bytes()
	return bytes.Equal(sig[:32], encodedR)
}

// Sign signs a hash with priv.
func Sign(priv ed25519.PrivateKey, hash crypto.Hash) []byte {
	signature := make([]byte, ed25519.SignatureSize)
	return sign(signature, priv, hash)
}

func sign(signature []byte, priv ed25519.PrivateKey, hash crypto.Hash) []byte {
	if l := len(priv); l != ed25519.PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	keyDigest := sha512.Sum512(priv[:32])
	expandedSecretKey := new(edwards25519.Scalar).SetBytesWithClamping(keyDigest[:32])

	buf := make([]byte, 96)
	copy(buf[:32], keyDigest[32:])
	copy(buf[32:], hash[:])
	messageDigest := sha512.Sum512(buf[:64])

	messageDigestReduced := new(edwards25519.Scalar).SetUniformBytes(messageDigest[:])
	encodedR := new(edwards25519.Point).ScalarBaseMult(messageDigestReduced).Bytes()

	copy(buf[:32], encodedR[:])
	copy(buf[32:], priv[32:])
	copy(buf[64:], hash[:])
	hramDigest := sha512.Sum512(buf[:96])
	hramDigestReduced := new(edwards25519.Scalar).SetUniformBytes(hramDigest[:])

	s := hramDigestReduced.Multiply(hramDigestReduced, expandedSecretKey)
	s.Add(s, messageDigestReduced)

	copy(signature[:32], encodedR)
	copy(signature[32:], s.Bytes())
	return signature
}

// ExtractPublicKey extracts the PublicKey portion of priv.
func ExtractPublicKey(priv ed25519.PrivateKey) ed25519.PublicKey {
	return ed25519.PublicKey(priv[32:])
}
