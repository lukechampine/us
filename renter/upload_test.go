package renter

import (
	"testing"

	"lukechampine.com/us/renterhost"
)

func BenchmarkIdealUpload(b *testing.B) {
	rsc := NewRSCode(10, 40)
	shards := make([][]byte, 40)
	for i := range shards {
		shards[i] = make([]byte, renterhost.SectorSize)
	}
	key := (&MetaFile{}).MasterKey
	nonce := make([]byte, 24)

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(shards[0])) * 10)
	for i := 0; i < b.N; i++ {
		for j := 10; j < len(shards); j++ {
			shards[j] = shards[j][:0]
		}
		rsc.Reconstruct(shards)
		for i := range shards {
			key.XORKeyStream(shards[i], nonce, 0)
		}
	}
}
