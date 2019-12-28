package renter

import (
	"bytes"
	"io/ioutil"
	"sync"
	"testing"
	"unsafe"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"lukechampine.com/frand"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

func TestCopySection(t *testing.T) {
	// construct "encrypted" sectors
	sectors := map[crypto.Hash][]byte{
		{0}: frand.Bytes(1024),
		{1}: frand.Bytes(1024),
		{2}: frand.Bytes(1024),
	}
	// construct shard from sector data
	slices := []SectorSlice{
		{MerkleRoot: crypto.Hash{0}, SegmentIndex: 0, NumSegments: 1, Nonce: [24]byte{0}},
		{MerkleRoot: crypto.Hash{1}, SegmentIndex: 1, NumSegments: 2, Nonce: [24]byte{1}},
		{MerkleRoot: crypto.Hash{1}, SegmentIndex: 4, NumSegments: 1, Nonce: [24]byte{1}},
		{MerkleRoot: crypto.Hash{0}, SegmentIndex: 7, NumSegments: 6, Nonce: [24]byte{0}},
		{MerkleRoot: crypto.Hash{2}, SegmentIndex: 0, NumSegments: 6, Nonce: [24]byte{2}},
	}
	var key KeySeed
	var shard []byte
	for _, s := range slices {
		off, n := s.SegmentIndex*merkle.SegmentSize, int(s.NumSegments*merkle.SegmentSize)
		shard = append(shard, sectors[s.MerkleRoot][off:][:n]...)
		key.XORKeyStream(shard[len(shard)-n:], s.Nonce[:], uint64(s.SegmentIndex))
	}

	tests := []struct {
		offset, length int64
	}{
		{512, 512},
		{64, 64},
		{0, 64},
		{0, 1024},
		{0, 128},
		{0, 0},
		{64, 0},
	}
	for _, test := range tests {
		sections, err := calcSections(slices, test.offset, test.length)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		cw := &cryptWriter{&buf, slices, key, test.offset}
		for _, s := range sections {
			// need to copy because cryptWriter modifies its argument
			data := append([]byte(nil), sectors[s.MerkleRoot][s.Offset:][:s.Length]...)
			cw.Write(data)
		}
		if !bytes.Equal(buf.Bytes(), shard[test.offset:][:test.length]) {
			t.Fatal("retrieved data does not match")
		}
	}
}

func BenchmarkIdealDownload(b *testing.B) {
	rsc := NewRSCode(10, 40)
	shards := make([][]byte, 40)
	for i := range shards {
		shards[i] = make([]byte, renterhost.SectorSize)
		if i%2 == 1 {
			shards[i] = shards[i][:0]
		}
	}
	key := (&MetaFile{}).MasterKey
	nonce := make([]byte, 24)

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(renterhost.SectorSize * 10)
	for i := 0; i < b.N; i++ {
		for i := range shards {
			if i%2 == 1 {
				shards[i] = shards[i][:0]
			}
		}
		var wg sync.WaitGroup
		wg.Add(len(shards[:10]))
		for i := range shards[:10] {
			go func(i int) {
				key.XORKeyStream(shards[i*2], nonce, 0)
				merkle.SectorRoot((*[renterhost.SectorSize]byte)(unsafe.Pointer(&shards[i*2][0])))
				wg.Done()
			}(i)
		}
		wg.Wait()
		rsc.Recover(ioutil.Discard, shards, 0, renterhost.SectorSize*10)
	}
}
