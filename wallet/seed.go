package wallet

import (
	"encoding/binary"

	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"golang.org/x/crypto/blake2b"
	"lukechampine.com/frand"
	"lukechampine.com/us/ed25519"
)

// A Seed generates addresses deterministically from some initial entropy.
//
// Seeds consist of 128 bits of entropy, and are represented to the user as a
// 12-word BIP39 mnemonic seed phrase. Internally, this entropy is hashed into a
// siad-compatible seed before it is used to derive keys. This means that Seeds
// can be imported into a siad wallet. (The reverse, however, is not possible.)
type Seed struct {
	entropy  [16]byte
	siadSeed modules.Seed
}

// String implements fmt.Stringer by encoding the seed as a 12-word BIP39
// mnemonic phrase.
func (s Seed) String() string {
	return encodeBIP39Phrase(s.entropy)
}

// SiadSeed returns a Sia-compatible form of the Seed. This form can be imported
// into a standard siad wallet.
func (s Seed) SiadSeed() modules.Seed {
	return s.siadSeed
}

// deriveKey derives the keypair for the specified index. Note that s.siaSeed is
// used in the derivation, not s.entropy; this is what allows Seeds to be used
// with standard siad wallets. s.entropy is only used to provide a shorter seed
// phrase in the String method.
func (s Seed) deriveKey(index uint64) ed25519.PrivateKey {
	buf := make([]byte, len(s.siadSeed)+8)
	ss := s.siadSeed // prevent s from escaping to heap
	n := copy(buf, ss[:])
	binary.LittleEndian.PutUint64(buf[n:], index)
	seed := blake2b.Sum256(buf)
	return ed25519.NewKeyFromSeed(seed[:])
}

// PublicKey derives the types.SiaPublicKey for the specified index.
func (s Seed) PublicKey(index uint64) types.SiaPublicKey {
	sk := s.deriveKey(index)
	return types.SiaPublicKey{
		Algorithm: types.SignatureEd25519,
		Key:       sk[len(sk)-ed25519.PublicKeySize:],
	}
}

// SecretKey derives the ed25519 private key for the specified index.
func (s Seed) SecretKey(index uint64) ed25519.PrivateKey {
	return s.deriveKey(index)
}

// SeedFromEntropy returns the Seed derived from the supplied entropy.
func SeedFromEntropy(entropy [16]byte) Seed {
	return Seed{
		entropy:  entropy,
		siadSeed: modules.Seed(blake2b.Sum256(entropy[:])),
	}
}

// SeedFromPhrase returns the Seed derived from the supplied phrase.
func SeedFromPhrase(phrase string) (Seed, error) {
	entropy, err := decodeBIP39Phrase(phrase)
	if err != nil {
		return Seed{}, err
	}
	return SeedFromEntropy(entropy), nil
}

// NewSeed returns a random Seed.
func NewSeed() Seed {
	var entropy [16]byte
	frand.Read(entropy[:])
	return SeedFromEntropy(entropy)
}
