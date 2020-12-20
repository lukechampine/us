package ed25519hash

import (
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
	"lukechampine.com/frand"
)

// VerifyBatch verifies a set of signatures. This provides a speedup of roughly
// 2x compared to verifying the signatures individually. However, if
// verification fails, the caller cannot determine which signatures were invalid
// without resorting to individual verification.
func VerifyBatch(keys []ed25519.PublicKey, hashes [][32]byte, sigs [][]byte) bool {
	// The batch verification equation from the original Ed25519 paper is:
	//
	//   [-sum(z_i * s_i)]B + sum([z_i]R_i) + sum([z_i * k_i]A_i) = 0
	//
	// where:
	// - A_i is the verification key;
	// - R_i is the signature's R value;
	// - s_i is the signature's s value;
	// - k_i is the hash of the message and other data;
	// - z_i is a random 128-bit scalar.
	//
	// However, this can produce inconsistent results in the presence of
	// adversarial signatures (signatures with nonzero torsion components). To
	// guard against this, we multiply the whole equation by the cofactor. See
	// https://hdevalence.ca/blog/2020-10-04-its-25519am for more details.

	// Ultimately, we'll be computing the summation via VarTimeMultiScalarMult,
	// which takes two slices: a []*Scalar and a []*Point. So we need those
	// slices to contain:
	//
	// scalars: -sum(z_i * s_i),    z_0,  z_1, ...   z_0*k_0,  z_1*k_1,  ...
	// points:         B,           R_0,  R_1, ...     A_0,      A_1,    ...
	//
	// As an optimization, we allocate all of the scalar and point values
	// up-front, rather than allocating each slice element individually. We also
	// split these slices up into their various components to make things a bit
	// more readable.
	svals := make([]edwards25519.Scalar, 1+len(sigs)+len(keys))
	scalars := make([]*edwards25519.Scalar, 1+len(sigs)+len(keys))
	for i := range scalars {
		scalars[i] = &svals[i]
	}
	Bcoeff := scalars[0]               // z_i * s_i
	Rcoeffs := scalars[1:][:len(sigs)] // z_i
	Acoeffs := scalars[1+len(sigs):]   // z_i * k_i

	pvals := make([]edwards25519.Point, 1+len(sigs)+len(keys))
	points := make([]*edwards25519.Point, 1+len(sigs)+len(keys))
	for i := range points {
		points[i] = &pvals[i]
	}
	B := points[0]
	Rs := points[1:][:len(sigs)]
	As := points[1+len(sigs):]

	// First, set B and decompress all points R_i and A_i.
	B.Set(edwards25519.NewGeneratorPoint())
	for i, sig := range sigs {
		if len(sig) != ed25519.SignatureSize || sig[63]&224 != 0 {
			return false
		} else if _, err := Rs[i].SetBytes(sig[:32]); err != nil {
			return false
		}
	}
	for i, pub := range keys {
		if l := len(pub); l != ed25519.PublicKeySize {
			return false
		} else if _, err := As[i].SetBytes(pub); err != nil {
			return false
		}
	}

	// Next, generate the random 128-bit coefficients z_i.
	buf := make([]byte, 32)
	for i := range Rcoeffs {
		frand.Read(buf[:16])
		Rcoeffs[i].SetCanonicalBytes(buf)
	}

	// Compute the coefficient for B.
	for i, sig := range sigs {
		s, err := new(edwards25519.Scalar).SetCanonicalBytes(sig[32:])
		if err != nil {
			return false
		}
		Bcoeff.MultiplyAdd(Rcoeffs[i], s, Bcoeff) // Bcoeff += z_i * s_i
	}
	Bcoeff.Negate(Bcoeff) // this term is subtracted in the summation

	// Compute the coefficients for each A_i.
	buf = make([]byte, 96)
	for i := range Acoeffs {
		copy(buf[:32], sigs[i][:32])
		copy(buf[32:], keys[i])
		copy(buf[64:], hashes[i][:])
		hram := sha512.Sum512(buf)
		k := new(edwards25519.Scalar).SetUniformBytes(hram[:])
		Acoeffs[i].Multiply(Rcoeffs[i], k)
	}

	// Multiply all the points by their coefficients, sum the results, and
	// multiply by the cofactor.
	sum := new(edwards25519.Point).VarTimeMultiScalarMult(scalars, points)
	sum.MultByCofactor(sum)
	return sum.Equal(edwards25519.NewIdentityPoint()) == 1
}

// VerifySingleKeyBatch verifies a set of signatures that were all produced by
// the same key. This provides a speedup of roughly 4x compared to verifying the
// signatures individually. However, if verification fails, the caller cannot
// determine which signatures were invalid without resorting to individual
// verification.
func VerifySingleKeyBatch(pub ed25519.PublicKey, hashes [][32]byte, sigs [][]byte) bool {
	// Since we only have one A point, we can accumulate all of its coefficients
	// together. That is, instead of:
	//
	//   sum([z_i * k_i]A_i)
	//
	// we compute:
	//
	//   [sum(z_i * k_i)]A

	svals := make([]edwards25519.Scalar, 1+len(sigs)+1)
	scalars := make([]*edwards25519.Scalar, 1+len(sigs)+1)
	for i := range scalars {
		scalars[i] = &svals[i]
	}
	Bcoeff := scalars[0]
	Rcoeffs := scalars[1:][:len(sigs)]
	Acoeff := scalars[1+len(sigs)]
	pvals := make([]edwards25519.Point, 1+len(sigs)+1)
	points := make([]*edwards25519.Point, 1+len(sigs)+1)
	for i := range points {
		points[i] = &pvals[i]
	}
	points[0].Set(edwards25519.NewGeneratorPoint())
	Rs := points[1:][:len(sigs)]
	A := points[1+len(sigs)]
	if l := len(pub); l != ed25519.PublicKeySize {
		return false
	} else if _, err := A.SetBytes(pub); err != nil {
		return false
	}
	for i, sig := range sigs {
		if len(sig) != ed25519.SignatureSize || sig[63]&224 != 0 {
			return false
		} else if _, err := Rs[i].SetBytes(sig[:32]); err != nil {
			return false
		}
		s, err := new(edwards25519.Scalar).SetCanonicalBytes(sig[32:])
		if err != nil {
			return false
		}
		buf := make([]byte, 96)
		frand.Read(buf[:16])
		Rcoeffs[i].SetCanonicalBytes(buf[:32])
		Bcoeff.MultiplyAdd(Rcoeffs[i], s, Bcoeff)
		copy(buf[:32], sig[:32])
		copy(buf[32:], pub)
		copy(buf[64:], hashes[i][:])
		hram := sha512.Sum512(buf)
		k := new(edwards25519.Scalar).SetUniformBytes(hram[:])
		Acoeff.MultiplyAdd(Rcoeffs[i], k, Acoeff)
	}
	Bcoeff.Negate(Bcoeff)
	sum := new(edwards25519.Point).VarTimeMultiScalarMult(scalars, points)
	sum.MultByCofactor(sum)
	return sum.Equal(edwards25519.NewIdentityPoint()) == 1
}
