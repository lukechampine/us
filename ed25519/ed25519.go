// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ed25519 implements the Ed25519 signature algorithm. See
// https://ed25519.cr.yp.to/.
//
// These functions are also compatible with the “Ed25519” function defined in
// https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-05.
package ed25519

// This code is a port of the public domain, “ref10” implementation of ed25519
// from SUPERCOP.

import (
	"bytes"
	"crypto/sha512"
	"strconv"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"lukechampine.com/us/ed25519/internal/edwards25519"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 64
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 64
	// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = 32
)

// PublicKey is the type of Ed25519 public keys.
type PublicKey []byte

// VerifyHash reports whether sig is a valid signature of hash by pub.
func (pub PublicKey) VerifyHash(hash crypto.Hash, sig []byte) bool {
	if l := len(pub); l != PublicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	if len(sig) != SignatureSize || sig[63]&224 != 0 {
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

// PrivateKey is an Ed25519 private key.
type PrivateKey []byte

// SignHash signs a hash with priv and returns a signature.
func (priv PrivateKey) SignHash(hash crypto.Hash) []byte {
	if l := len(priv); l != PrivateKeySize {
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

	signature := make([]byte, SignatureSize)
	copy(signature[:32], encodedR[:])
	copy(signature[32:], s[:])
	return signature
}

// PublicKey returns the PublicKey corresponding to priv.
func (priv PrivateKey) PublicKey() PublicKey {
	return PublicKey(priv[32:])
}

// NewKeyFromSeed calculates a private key from a seed. It will panic if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func NewKeyFromSeed(seed []byte) PrivateKey {
	if l := len(seed); l != SeedSize {
		panic("ed25519: bad seed length: " + strconv.Itoa(l))
	}

	digest := sha512.Sum512(seed)
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var A edwards25519.ExtendedGroupElement
	var hBytes [32]byte
	copy(hBytes[:], digest[:])
	edwards25519.GeScalarMultBase(&A, &hBytes)
	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)

	privateKey := make([]byte, PrivateKeySize)
	copy(privateKey, seed)
	copy(privateKey[32:], publicKeyBytes[:])

	return privateKey
}
