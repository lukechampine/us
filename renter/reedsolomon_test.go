package renter

import (
	"bytes"
	"io/ioutil"
	"reflect"
	"testing"

	"gitlab.com/NebulousLabs/fastrand"
	"lukechampine.com/us/renterhost"
)

func checkRecover(rsc ErasureCoder, shards [][]byte, data []byte) bool {
	var buf bytes.Buffer
	if err := rsc.Recover(&buf, shards, len(data)); err != nil {
		return false
	}
	return bytes.Equal(buf.Bytes(), data)
}

func TestReedSolomon(t *testing.T) {
	// 1-of-10 code
	rsc := NewRSCode(1, 10)
	data := fastrand.Bytes(1023)
	shards := rsc.Encode(data)
	// delete 3 random shards
	partialShards := append([][]byte(nil), shards...)
	for i := 0; i < 3; i++ {
		partialShards[fastrand.Intn(len(partialShards))] = nil
	}
	// reconstruct
	if err := rsc.Reconstruct(partialShards); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(shards, partialShards) {
		t.Error("failed to reconstruct shards")
	}

	// delete 3 random shards
	for i := 0; i < 3; i++ {
		partialShards[fastrand.Intn(len(partialShards))] = nil
	}
	// recover
	if !checkRecover(rsc, partialShards, data) {
		t.Error("failed to recover shards")
	}

	// 7-of-7 code (simple redundancy)
	rsc = NewRSCode(7, 7)
	shards = rsc.Encode(data)
	// delete a random shard
	partialShards = append([][]byte(nil), shards...)
	partialShards[fastrand.Intn(len(partialShards))] = nil
	// reconstruct should fail
	if err := rsc.Reconstruct(partialShards); err == nil {
		t.Error("Reconstruct should have failed with missing shard")
	}

	// recover
	if checkRecover(rsc, partialShards, data) {
		t.Error("Recover should have failed with missing shard")
	}
	if !checkRecover(rsc, shards, data) {
		t.Error("failed to recover shards")
	}
}

func BenchmarkReedSolomon(b *testing.B) {
	benchEncode := func(n, m int, data []byte) func(*testing.B) {
		rsc := NewRSCode(n, m)
		return func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				rsc.Encode(data)
			}
		}
	}

	benchReconstruct := func(n, m, r int, data []byte) func(*testing.B) {
		rsc := NewRSCode(n, m)
		shards := rsc.Encode(data)
		return func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(shards[0]) * r))
			for i := 0; i < b.N; i++ {
				for j := range shards[:r] {
					shards[j] = shards[j][:0]
				}
				if err := rsc.Reconstruct(shards); err != nil {
					b.Fatal(err)
				}
			}
		}
	}

	benchJoin := func(n, m int, data []byte) func(*testing.B) {
		rsc := NewRSCode(n, m)
		shards := rsc.Encode(data)
		return func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				if err := rsc.Recover(ioutil.Discard, shards, len(data)); err != nil {
					b.Fatal(err)
				}
			}
		}
	}

	data := make([]byte, renterhost.SectorSize*4+100)
	fastrand.Read(data[:renterhost.SectorSize])
	b.Run("encode-10-of-40-naive", benchEncode(10, 40, data[:renterhost.SectorSize:renterhost.SectorSize]))
	b.Run("encode-10-of-40-padded", benchEncode(10, 40, data[:renterhost.SectorSize]))
	b.Run("encode-40-of-40-naive", benchEncode(40, 40, data[:renterhost.SectorSize]))
	b.Run("encode-40-of-40-padded", benchEncode(40, 40, data[:renterhost.SectorSize+40-(renterhost.SectorSize%40)]))

	b.Run("reconstruct-1-of-10-of-40", benchReconstruct(10, 40, 1, data[:renterhost.SectorSize:renterhost.SectorSize]))
	b.Run("reconstruct-10-of-10-of-40", benchReconstruct(10, 40, 10, data[:renterhost.SectorSize:renterhost.SectorSize]))

	b.Run("join-10-of-40", benchJoin(10, 40, data[:renterhost.SectorSize:renterhost.SectorSize]))
	b.Run("join-40-of-40", benchJoin(40, 40, data[:renterhost.SectorSize]))
}
