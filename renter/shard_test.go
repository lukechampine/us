package renter

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"gitlab.com/NebulousLabs/fastrand"
)

func testShardFile(tb testing.TB) (*Shard, func()) {
	tb.Helper()
	name := filepath.Join(os.TempDir(), tb.Name()+hex.EncodeToString(fastrand.Bytes(6)))
	os.RemoveAll(name)
	s, err := OpenShard(name)
	if err != nil {
		tb.Fatal(err)
	}
	return s, func() {
		s.Close()
		os.RemoveAll(name)
	}
}

func TestShard(t *testing.T) {
	sf, cleanup := testShardFile(t)
	defer cleanup()
	// write a bunch of random slices in random places
	slices := make(map[int64]SectorSlice)
	for i := 0; i < 20; i++ {
		s := SectorSlice{
			SegmentIndex: uint32(fastrand.Uint64n(20)),
			NumSegments:  uint32(fastrand.Uint64n(20)),
		}
		fastrand.Read(s.MerkleRoot[:])
		fastrand.Read(s.Checksum[:])
		slices[int64(fastrand.Intn(20))] = s
	}
	for index, s := range slices {
		if err := sf.WriteSlice(s, index); err != nil {
			t.Fatal(err)
		}
	}
	name := filepath.Join(sf.f.Name())

	// read back the written slices
	ss, err := ReadShard(name)
	if err != nil {
		t.Fatal(err)
	}
	for index, s := range slices {
		if ss[index] != s {
			t.Errorf("unexpected slice at index %v: expected %v, got %v", index, s, ss[index])
		}
	}
}

func BenchmarkShardWriteSlice(b *testing.B) {
	sf, cleanup := testShardFile(b)
	defer cleanup()

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(SectorSliceSize)
	for i := 0; i < b.N; i++ {
		if err := sf.WriteSlice(SectorSlice{}, int64(i)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkShardWriteSliceP(b *testing.B) {
	const numThreads = 10
	files := make([]*Shard, numThreads)
	for i := range files {
		sf, cleanup := testShardFile(b)
		defer cleanup()
		files[i] = sf
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(SectorSliceSize * numThreads)
	var wg sync.WaitGroup
	wg.Add(numThreads)
	for i := 0; i < numThreads; i++ {
		go func(sf *Shard) {
			for i := 0; i < b.N; i++ {
				if err := sf.WriteSlice(SectorSlice{}, int64(i)); err != nil {
					panic(err)
				}
			}
			wg.Done()
		}(files[i])
	}
	wg.Wait()
}
