package renter

import (
	"sync"
	"testing"
	"unsafe"

	"lukechampine.com/frand"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

func BenchmarkIdealUpload(b *testing.B) {
	const numHosts = 40
	const minShards = 30
	rsc := NewRSCode(minShards, numHosts)
	data := frand.Bytes(renterhost.SectorSize * minShards)
	shards := make([][]byte, numHosts)
	for i := range shards {
		shards[i] = make([]byte, renterhost.SectorSize)
	}
	var key KeySeed
	nonce := make([]byte, 24)

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(renterhost.SectorSize * numHosts))
	for i := 0; i < b.N; i++ {
		for j := range shards {
			shards[j] = shards[j][:0]
		}
		rsc.Encode(data, shards)
		var wg sync.WaitGroup
		wg.Add(len(shards))
		for i := range shards {
			go func(i int) {
				key.XORKeyStream(shards[i], nonce, 0)
				merkle.SectorRoot((*[renterhost.SectorSize]byte)(unsafe.Pointer(&shards[i][0])))
				wg.Done()
			}(i)
		}
		wg.Wait()
	}
}
