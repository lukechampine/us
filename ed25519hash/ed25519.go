// Package ed25519hash provides optimized routines for signing and verifying Sia
// hashes.
package ed25519hash

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"strconv"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"lukechampine.com/us/ed25519hash/internal/edwards25519"
)

// Verify reports whether sig is a valid signature of hash by pub.
func Verify(pub ed25519.PublicKey, hash crypto.Hash, sig []byte) bool {
	if l := len(pub); l != ed25519.PublicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	if len(sig) != ed25519.SignatureSize || sig[63]&224 != 0 {
		return false
	}

	var A edwards25519.ExtendedGroupElement
	var publicKeyBytes [32]byte
	copy(publicKeyBytes[:], pub)
	if !A.FromBytes(&publicKeyBytes) {
		return false
	}
	edwards25519.FeNeg(&A.X, &A.X)
	edwards25519.FeNeg(&A.T, &A.T)

	buf := make([]byte, 96)
	copy(buf[:32], sig[:32])
	copy(buf[32:], pub)
	copy(buf[64:], hash[:])
	digest := sha512.Sum512(buf)

	var hReduced [32]byte
	edwards25519.ScReduce(&hReduced, &digest)

	var R edwards25519.ProjectiveGroupElement
	var b [32]byte
	copy(b[:], sig[32:])
	edwards25519.GeDoubleScalarMultVartime(&R, &hReduced, &A, &b)

	var checkR [32]byte
	R.ToBytes(&checkR)
	return bytes.Equal(sig[:32], checkR[:])
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

	digest1 := sha512.Sum512(priv[:32])

	var expandedSecretKey [32]byte
	copy(expandedSecretKey[:], digest1[:32])
	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 63
	expandedSecretKey[31] |= 64

	buf := make([]byte, 96)
	copy(buf[:32], digest1[32:])
	copy(buf[32:], hash[:])
	messageDigest := sha512.Sum512(buf[:64])

	var messageDigestReduced [32]byte
	edwards25519.ScReduce(&messageDigestReduced, &messageDigest)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &messageDigestReduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	copy(buf[:32], encodedR[:])
	copy(buf[32:], priv[32:])
	copy(buf[64:], hash[:])
	hramDigest := sha512.Sum512(buf[:96])

	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	var s [32]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &expandedSecretKey, &messageDigestReduced)

	copy(signature[:32], encodedR[:])
	copy(signature[32:], s[:])
	return signature
}

// ExtractPublicKey extracts the PublicKey portion of priv.
func ExtractPublicKey(priv ed25519.PrivateKey) ed25519.PublicKey {
	return ed25519.PublicKey(priv[32:])
}
