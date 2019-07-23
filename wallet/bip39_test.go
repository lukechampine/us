package wallet

import (
	"encoding/hex"
	"testing"

	"lukechampine.com/frand"
)

func TestBIP39Vectors(t *testing.T) {
	tests := []struct {
		entropy string
		phrase  string
	}{
		{
			entropy: "00000000000000000000000000000000",
			phrase:  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		},
		{
			entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
			phrase:  "legal winner thank year wave sausage worth useful legal winner thank yellow",
		},
		{
			entropy: "80808080808080808080808080808080",
			phrase:  "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
		},
		{
			entropy: "ffffffffffffffffffffffffffffffff",
			phrase:  "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
		},
		{
			entropy: "77c2b00716cec7213839159e404db50d",
			phrase:  "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
		},
		{
			entropy: "0460ef47585604c5660618db2e6a7e7f",
			phrase:  "afford alter spike radar gate glance object seek swamp infant panel yellow",
		},
		{
			entropy: "eaebabb2383351fd31d703840b32e9e2",
			phrase:  "turtle front uncle idea crush write shrug there lottery flower risk shell",
		},
		{
			entropy: "18ab19a9f54a9274f03e5209a2ac8a91",
			phrase:  "board flee heavy tunnel powder denial science ski answer betray cargo cat",
		},
	}
	for _, test := range tests {
		var entropy [16]byte
		hex.Decode(entropy[:], []byte(test.entropy))

		phrase := encodeBIP39Phrase(entropy)
		if phrase != test.phrase {
			t.Error("encoded wrong phrase for", test.phrase)
		}

		dec, err := decodeBIP39Phrase(test.phrase)
		if err != nil {
			t.Error("failed to decode valid phrase", test.phrase)
		} else if dec != entropy {
			t.Error("decoded wrong entropy for", test.phrase)
		}
	}
}

func TestDecodeBIP39Phrase(t *testing.T) {
	// 1000 random phrases
	for i := 0; i < 512; i++ {
		var entropy [16]byte
		frand.Read(entropy[:])
		phrase := encodeBIP39Phrase(entropy)
		dec, err := decodeBIP39Phrase(phrase)
		if err != nil {
			t.Error("failed to decode valid phrase", phrase)
		} else if dec != entropy {
			t.Error("decoded wrong entropy for", phrase)
		}
	}

	// invalid phrases
	invalid := []string{
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
		"legal winner thank year wave sausage worth useful legal winner thank yellow yellow",
		"letter advice cage absurd amount doctor acoustic avoid letter advice caged above",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo, wrong",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
		"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will will will",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always.",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo why",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art art",
		"legal winner thank year wave sausage worth useful legal winner thanks year wave worth useful legal winner thank year wave sausage worth title",
		"letter advice cage absurd amount doctor acoustic avoid letters advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo voted",
		"jello better achieve collect unaware mountain thought cargo oxygen act hood bridge",
		"renew, stay, biology, evidence, goat, welcome, casual, join, adapt, armor, shuffle, fault, little, machine, walk, stumble, urge, swap",
		"dignity pass list indicate nasty",
	}
	for _, phrase := range invalid {
		if _, err := decodeBIP39Phrase(phrase); err == nil {
			t.Error("decoding should have failed for", phrase)
		}
	}
}

func BenchmarkBIP39(b *testing.B) {
	b.Run("encode", func(b *testing.B) {
		var entropy [16]byte
		frand.Read(entropy[:])
		for i := 0; i < b.N; i++ {
			encodeBIP39Phrase(entropy)
		}
	})
	b.Run("decode", func(b *testing.B) {
		var entropy [16]byte
		frand.Read(entropy[:])
		phrase := encodeBIP39Phrase(entropy)
		for i := 0; i < b.N; i++ {
			decodeBIP39Phrase(phrase)
		}
	})
}
