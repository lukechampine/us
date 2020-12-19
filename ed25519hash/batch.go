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

	// save some heap allocations by allocating all scalar and point values
	// together
	svals := make([]edwards25519.Scalar, 1+len(sigs)+len(keys))
	pvals := make([]edwards25519.Point, 1+len(sigs)+len(keys))

	scalars := make([]*edwards25519.Scalar, 1+len(sigs)+len(keys))
	for i := range scalars {
		scalars[i] = &svals[i]
	}
	Bcoeff := scalars[0]               // z_i * s_i
	Rcoeffs := scalars[1:][:len(sigs)] // z_i
	Acoeffs := scalars[1+len(sigs):]   // z_i * k_i

	points := make([]*edwards25519.Point, 1+len(keys)+len(sigs))
	for i := range points {
		points[i] = &pvals[i]
	}
	points[0].Set(edwards25519.NewGeneratorPoint())
	Rs := points[1:][:len(sigs)]
	As := points[1+len(sigs):]

	for i := range sigs {
		pub := keys[i]
		hash := hashes[i]
		sig := sigs[i]

		// decompress A
		if l := len(pub); l != ed25519.PublicKeySize {
			return false
		} else if _, err := As[i].SetBytes(pub); err != nil {
			return false
		}

		// decompress R
		if len(sig) != ed25519.SignatureSize || sig[63]&224 != 0 {
			return false
		} else if _, err := Rs[i].SetBytes(sig[:32]); err != nil {
			return false
		}

		// generate z
		buf := make([]byte, 96)
		frand.Read(buf[:16])
		z, _ := Rcoeffs[i].SetCanonicalBytes(buf[:32])

		// decode s
		s, err := new(edwards25519.Scalar).SetCanonicalBytes(sig[32:])
		if err != nil {
			return false
		}
		Bcoeff.MultiplyAdd(s, z, Bcoeff)

		// compute k
		copy(buf[:32], sig[:32])
		copy(buf[32:], pub)
		copy(buf[64:], hash[:])
		hramDigest := sha512.Sum512(buf)
		k := Acoeffs[i].SetUniformBytes(hramDigest[:])
		Acoeffs[i] = k.Multiply(k, z)
	}
	Bcoeff.Negate(Bcoeff) // this term is negative

	// multiply each point by its scalar coefficient, and sum the products
	check := new(edwards25519.Point).VarTimeMultiScalarMult(scalars, points)
	check.MultByCofactor(check)
	return check.Equal(edwards25519.NewIdentityPoint()) == 1
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
	//   [sum(z_i * k_i)]A_i

	svals := make([]edwards25519.Scalar, 1+len(sigs)+1)
	pvals := make([]edwards25519.Point, 1+len(sigs)+1)
	scalars := make([]*edwards25519.Scalar, 1+len(sigs)+1)
	for i := range scalars {
		scalars[i] = &svals[i]
	}
	Bcoeff := scalars[0]
	Rcoeffs := scalars[1:][:len(sigs)]
	Acoeff := scalars[1+len(sigs)]
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
	for i := range sigs {
		hash := hashes[i]
		sig := sigs[i]
		if len(sig) != ed25519.SignatureSize || sig[63]&224 != 0 {
			return false
		} else if _, err := Rs[i].SetBytes(sig[:32]); err != nil {
			return false
		}
		buf := make([]byte, 96)
		frand.Read(buf[:16])
		z, _ := Rcoeffs[i].SetCanonicalBytes(buf[:32])
		s, err := new(edwards25519.Scalar).SetCanonicalBytes(sig[32:])
		if err != nil {
			return false
		}
		Bcoeff.MultiplyAdd(s, z, Bcoeff)
		copy(buf[:32], sig[:32])
		copy(buf[32:], pub)
		copy(buf[64:], hash[:])
		hramDigest := sha512.Sum512(buf)
		k := new(edwards25519.Scalar).SetUniformBytes(hramDigest[:])
		Acoeff.MultiplyAdd(k, z, Acoeff)
	}
	Bcoeff.Negate(Bcoeff)
	check := new(edwards25519.Point).VarTimeMultiScalarMult(scalars, points)
	check.MultByCofactor(check)
	return check.Equal(edwards25519.NewIdentityPoint()) == 1
}
