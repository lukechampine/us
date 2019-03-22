package renter

import (
	"io/ioutil"
	"testing"

	"lukechampine.com/us/renterhost"
)

func BenchmarkIdealDownload(b *testing.B) {
	rsc := NewRSCode(10, 40)
	shards := make([][]byte, 40)
	for i := range shards {
		shards[i] = make([]byte, renterhost.SectorSize)
		if i%2 == 0 {
			shards[i] = shards[i][:0]
		}
	}
	key := (&MetaFile{}).EncryptionKey(0)
	nonce := make([]byte, 24)

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(renterhost.SectorSize * 10)
	for i := 0; i < b.N; i++ {
		for i := range shards[:10] {
			key.XORKeyStream(shards[i*2], nonce, 0)
		}
		rsc.Recover(ioutil.Discard, shards, renterhost.SectorSize*10)
	}
}
