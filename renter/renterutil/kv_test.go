package renterutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"testing/iotest"
	"time"

	"lukechampine.com/frand"
	"lukechampine.com/us/internal/ghost"
	"lukechampine.com/us/renterhost"
)

func createTestingKV(tb testing.TB, numHosts, m, n int) PseudoKV {
	tb.Helper()
	hosts := make([]*ghost.Host, numHosts)
	hkr := make(testHKR)
	hs := NewHostSet(hkr, 0)
	for i := range hosts {
		h, c := createHostWithContract(tb)
		hosts[i] = h
		hkr[h.PublicKey] = h.Settings.NetAddress
		hs.AddHost(c)
		tb.Cleanup(func() { h.Close() })
	}

	// use ephemeral DB during short tests
	var db MetaDB
	if true || testing.Short() {
		db = NewEphemeralMetaDB()
	} else {
		dir, err := ioutil.TempDir("", tb.Name())
		if err != nil {
			tb.Fatal(err)
		}
		os.MkdirAll(dir, 0700)
		tb.Cleanup(func() { os.RemoveAll(dir) })
		dbName := filepath.Join(dir, "kv.db")
		db, err = NewBoltMetaDB(dbName)
		if err != nil {
			tb.Fatal(err)
		}
	}
	kv := PseudoKV{
		DB:         db,
		M:          m,
		N:          n,
		P:          3, // TODO: is this a sane default?
		Uploader:   ParallelChunkUploader{Hosts: hs},
		Downloader: ParallelChunkDownloader{Hosts: hs},
		Deleter:    SerialSectorDeleter{Hosts: hs},
	}
	tb.Cleanup(func() { kv.Close() })

	return kv
}

func TestKVPutGet(t *testing.T) {
	ctx := context.Background()
	kv := createTestingKV(t, 3, 2, 3)

	err := kv.PutBytes(ctx, []byte("foo"), []byte("bar"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := kv.GetBytes(ctx, []byte("foo"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "bar" {
		t.Fatalf("bad data: %q", data)
	}

	// large value, using streaming API
	bigdata := frand.Bytes(renterhost.SectorSize * 4)
	err = kv.Put(ctx, []byte("foo"), bytes.NewReader(bigdata))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = kv.Get(ctx, []byte("foo"), &buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), bigdata) {
		t.Fatal("bad data")
	}

	// range request
	buf.Reset()
	off, n := int64(renterhost.SectorSize+10), int64(497)
	err = kv.GetRange(ctx, []byte("foo"), &buf, off, n)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), bigdata[off:][:n]) {
		t.Fatal("bad range data", len(buf.Bytes()), bytes.Index(bigdata, buf.Bytes()))
	}
}

func TestKVBufferHosts(t *testing.T) {
	ctx := context.Background()
	kv := createTestingKV(t, 6, 2, 3) // 3 buffer hosts

	bigdata := frand.Bytes(renterhost.SectorSize * 6)
	err := kv.Put(ctx, []byte("foo"), bytes.NewReader(bigdata))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err = kv.Get(ctx, []byte("foo"), &buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), bigdata) {
		t.Fatal("bad data")
	}

	// check that chunks are stored on different hosts
	var chunkHosts []string
	b, err := kv.DB.Blob([]byte("foo"))
	if err != nil {
		t.Fatal(err)
	}
	for _, cid := range b.Chunks {
		c, err := kv.DB.Chunk(cid)
		if err != nil {
			t.Fatal(err)
		}
		var hosts string
		for _, ssid := range c.Shards {
			s, err := kv.DB.Shard(ssid)
			if err != nil {
				t.Fatal(err)
			}
			hosts += s.HostKey.ShortKey()
		}
		chunkHosts = append(chunkHosts, hosts)
	}
	allEqual := true
	for i := range chunkHosts[1:] {
		allEqual = allEqual && chunkHosts[i] == chunkHosts[i+1]
	}
	if allEqual {
		t.Fatal("all chunks stored on the same host set")
	}
}

func TestKVResumeReader(t *testing.T) {
	ctx := context.Background()
	kv := createTestingKV(t, 3, 2, 3)

	bigdata := frand.Bytes(renterhost.SectorSize * 4)
	r := bytes.NewReader(bigdata)
	err := kv.Put(ctx, []byte("foo"), &errorAfterNReader{
		R:   r,
		N:   renterhost.SectorSize * 3,
		Err: iotest.ErrTimeout, // arbitrary
	})
	if err != iotest.ErrTimeout {
		t.Fatal(err)
	}

	// TODO: unsure whether this should return an error
	if false {
		_, err = kv.GetBytes(ctx, []byte("foo"))
		if err == nil {
			t.Fatal("expected Get of incomplete upload to fail")
		}
	}

	// resume
	err = kv.Resume(ctx, []byte("foo"), r)
	if err != nil {
		t.Fatal(err)
	}
	data, err := kv.GetBytes(ctx, []byte("foo"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, bigdata) {
		t.Fatal("bad data")
	}
}

func TestKVResumeHost(t *testing.T) {
	ctx := context.Background()
	hosts := make([]*ghost.Host, 3)
	hkr := make(testHKR)
	hs := NewHostSet(hkr, 0)
	for i := range hosts {
		h, c := createHostWithContract(t)
		defer h.Close()
		hosts[i] = h
		hkr[h.PublicKey] = h.Settings.NetAddress
		hs.AddHost(c)
	}
	db := NewEphemeralMetaDB()
	kv := PseudoKV{
		DB: db,
		M:  2,
		N:  3,
		P:  2,

		Uploader:   ParallelChunkUploader{Hosts: hs},
		Downloader: SerialChunkDownloader{Hosts: hs},
	}

	bigdata := frand.Bytes(renterhost.SectorSize * 4)
	r := bytes.NewReader(bigdata)
	err := kv.Put(ctx, []byte("foo"), &fnAfterNReader{
		R: r,
		N: renterhost.SectorSize * 2,
		Fn: func() {
			hosts[1].Close()
			s, err := hs.acquire(hosts[1].PublicKey)
			if err != nil {
				return
			}
			s.Close()
			hs.release(hosts[1].PublicKey)
		},
	})
	if err == nil {
		t.Fatal("expected upload to fail")
	}

	// replace host 0 with a new host
	h, c := createHostWithContract(t)
	defer h.Close()
	hkr[h.PublicKey] = h.Settings.NetAddress
	delete(hs.sessions, hosts[1].PublicKey)
	hs.AddHost(c)

	// resume
	err = kv.Resume(ctx, []byte("foo"), r)
	if err != nil {
		t.Fatal(err)
	}
	// TODO: verify that existing shards were not re-uploaded

	// the first chunk is still stored on the bad host, but we should be able to
	// download from the other hosts
	data, err := kv.GetBytes(ctx, []byte("foo"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, bigdata) {
		t.Fatal("bad data")
	}
}

func TestKVUpdate(t *testing.T) {
	ctx := context.Background()
	kv := createTestingKV(t, 3, 2, 3)

	bigdata := frand.Bytes(renterhost.SectorSize * 4)
	err := kv.PutBytes(ctx, []byte("foo"), bigdata)
	if err != nil {
		t.Fatal(err)
	}

	kv2 := createTestingKV(t, 4, 3, 4)
	gcu := GenericChunkUpdater{
		D: kv.Downloader,
		U: kv2.Uploader,
		M: 3,
		N: 4,
	}
	err = kv.Update(ctx, []byte("foo"), SerialBlobUpdater{gcu})
	if err != nil {
		t.Fatal(err)
	}

	// should no longer be possible to download from old kv
	_, err = kv.GetBytes(ctx, []byte("foo"))
	if err == nil {
		t.Fatal("expected error")
	}
	// should be possible with new downloader, though
	kv.Downloader = kv2.Downloader
	data, err := kv.GetBytes(ctx, []byte("foo"))
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(data, bigdata) {
		t.Fatal("bad data")
	}
}

func TestKVMigrate(t *testing.T) {
	ctx := context.Background()
	kv := createTestingKV(t, 3, 2, 3)

	bigdata := frand.Bytes(renterhost.SectorSize * 4)
	err := kv.PutBytes(ctx, []byte("foo"), bigdata)
	if err != nil {
		t.Fatal(err)
	}

	// replace a host in the set
	hs := kv.Uploader.(ParallelChunkUploader).Hosts
	for hostKey := range hs.sessions {
		s, _ := hs.acquire(hostKey)
		s.Close()
		hs.release(hostKey)
		delete(hs.sessions, hostKey)
		break
	}
	h, c := createHostWithContract(t)
	defer h.Close()
	hs.hkr.(testHKR)[h.PublicKey] = h.Settings.NetAddress
	hs.AddHost(c)

	// migrate
	err = kv.Migrate(ctx, []byte("foo"), hs)
	if err != nil {
		t.Fatal(err)
	}

	data, err := kv.GetBytes(ctx, []byte("foo"))
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(data, bigdata) {
		t.Fatal("bad data", data, bigdata)
	}
}

func TestKVGC(t *testing.T) {
	ctx := context.Background()
	kv := createTestingKV(t, 3, 2, 3)

	bigdata := frand.Bytes(renterhost.SectorSize * 4)
	err := kv.PutBytes(ctx, []byte("foo"), bigdata)
	if err != nil {
		t.Fatal(err)
	}

	if err := kv.Delete([]byte("foo")); err != nil {
		t.Fatal(err)
	}
	if err := kv.GC(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := kv.GetBytes(ctx, []byte("foo")); err != ErrKeyNotFound {
		t.Fatalf("expected %v, got %v", ErrKeyNotFound, err)
	}
}

func TestKVPutGetParallel(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	ctx := context.Background()
	kv := createTestingKV(t, 6, 2, 3)
	hs := kv.Uploader.(ParallelChunkUploader).Hosts
	kv.Uploader = ParallelChunkUploader{Hosts: hs}
	kv.Downloader = ParallelChunkDownloader{Hosts: hs}

	var kvs [5]struct {
		smallKey []byte
		smallVal []byte
		largeKey []byte
		largeVal []byte
	}
	for i := range kvs {
		kvs[i].smallKey = []byte("small" + strconv.Itoa(i))
		kvs[i].smallVal = []byte("value" + strconv.Itoa(i))
		kvs[i].largeKey = []byte("large" + strconv.Itoa(i))
		kvs[i].largeVal = frand.Bytes(renterhost.SectorSize * 4)
	}
	// spawn multiple goroutines uploading in parallel
	errCh := make(chan error)
	for i := range kvs {
		go func(i int) {
			errCh <- func() error {
				err := kv.PutBytes(ctx, kvs[i].smallKey, kvs[i].smallVal)
				if err != nil {
					return err
				}
				return kv.Put(ctx, kvs[i].largeKey, bytes.NewReader(kvs[i].largeVal))
			}()
		}(i)
	}
	for range kvs {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	// spawn multiple goroutines downloading in parallel
	// TODO: make one host fail
	for i := range kvs {
		go func(i int) {
			errCh <- func() error {
				data, err := kv.GetBytes(ctx, kvs[i].smallKey)
				if err != nil {
					return err
				} else if !bytes.Equal(data, kvs[i].smallVal) {
					return fmt.Errorf("bad data: %q", data)
				}
				var buf bytes.Buffer
				err = kv.Get(ctx, []byte(kvs[i].largeKey), &buf)
				if err != nil {
					return err
				} else if !bytes.Equal(buf.Bytes(), kvs[i].largeVal) {
					return fmt.Errorf("bad data")
				}
				// range request
				buf.Reset()
				off, n := int64(renterhost.SectorSize+10*(i+1)), int64(497*(i+1))
				err = kv.GetRange(ctx, kvs[i].largeKey, &buf, off, n)
				if err != nil {
					return err
				} else if !bytes.Equal(buf.Bytes(), kvs[i].largeVal[off:][:n]) {
					return fmt.Errorf("bad range data")
				}
				return nil
			}()
		}(i)
	}
	for range kvs {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
}

func TestKVMinimumAvailability(t *testing.T) {
	ctx := context.Background()
	kv := createTestingKV(t, 3, 1, 3)
	hs := kv.Uploader.(ParallelChunkUploader).Hosts
	kv.Uploader = MinimumChunkUploader{Hosts: hs}

	bigdata := frand.Bytes(renterhost.SectorSize * 4)
	err := kv.Put(ctx, []byte("foo"), bytes.NewReader(bigdata))
	if err != nil {
		t.Fatal(err)
	}

	// only one shard should have been uploaded
	var totalUploaded uint64
	for _, ls := range hs.sessions {
		if ls.s != nil {
			totalUploaded += ls.s.Revision().Revision.NewFileSize
		}
	}
	if totalUploaded != uint64(len(bigdata)) {
		t.Fatal("expected 1x redundancy, got", float64(totalUploaded)/float64(len(bigdata)))
	}

	// should be able to download
	data, err := kv.GetBytes(ctx, []byte("foo"))
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(data, bigdata) {
		t.Fatal("bad data")
	}

	// resume to full redundancy
	kv.Uploader = ParallelChunkUploader{Hosts: hs}
	err = kv.Resume(ctx, []byte("foo"), bytes.NewReader(bigdata))
	if err != nil {
		t.Fatal(err)
	}

	data, err = kv.GetBytes(ctx, []byte("foo"))
	if err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(data, bigdata) {
		t.Fatal("bad data")
	}
}

func wasCanceled(err error) bool {
	err = errors.Unwrap(err)
	switch err := err.(type) {
	case *HostError:
		return err.Err == context.Canceled || err.Err == context.DeadlineExceeded
	case HostErrorSet:
		return err[0].Err == context.Canceled || err[0].Err == context.DeadlineExceeded
	default:
		return false
	}
}

func TestKVCancel(t *testing.T) {
	kv := createTestingKV(t, 3, 2, 3)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := kv.PutBytes(ctx, []byte("foo"), []byte("bar"))
	if !wasCanceled(err) {
		t.Fatal("expected cancel, got", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	err = kv.PutBytes(ctx, []byte("foo"), []byte("bar"))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	data, err := kv.GetBytes(ctx, []byte("foo"))
	if !wasCanceled(err) {
		t.Fatal("expected cancel, got", err)
	}
	ctx = context.Background()
	data, err = kv.GetBytes(ctx, []byte("foo"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "bar" {
		t.Fatalf("bad data: %q", data)
	}

	// large value, using streaming API
	bigdata := frand.Bytes(renterhost.SectorSize * 4)
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	err = kv.Put(ctx, []byte("foo"), bytes.NewReader(bigdata))
	if !wasCanceled(err) {
		t.Fatal("expected cancel, got", err)
	}
	cancel()
	ctx = context.Background()
	err = kv.Put(ctx, []byte("foo"), bytes.NewReader(bigdata))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	var buf bytes.Buffer
	err = kv.Get(ctx, []byte("foo"), &buf)
	if !wasCanceled(err) {
		t.Fatal("expected cancel, got", err)
	}
	cancel()
	ctx = context.Background()
	buf.Reset()
	err = kv.Get(ctx, []byte("foo"), &buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), bigdata) {
		t.Fatal("bad data")
	}
}

func TestKVBuffering(t *testing.T) {
	t.Skip("TODO: store multiple values in one sector")
}

type errorAfterNReader struct {
	R   io.Reader
	N   int
	Err error
}

func (enr *errorAfterNReader) Read(p []byte) (int, error) {
	n := enr.N
	if n == 0 {
		return 0, enr.Err
	} else if n > len(p) {
		n = len(p)
	}
	read, err := enr.R.Read(p[:n])
	enr.N -= read
	return read, err
}

type fnAfterNReader struct {
	R  io.Reader
	N  int
	Fn func()
}

func (fnr *fnAfterNReader) Read(p []byte) (int, error) {
	if fnr.Fn != nil {
		n := fnr.N
		if n == 0 {
			fnr.Fn()
			fnr.Fn = nil
			n = len(p)
		} else if n > len(p) {
			n = len(p)
		}
		p = p[:n]
	}
	read, err := fnr.R.Read(p)
	fnr.N -= read
	return read, err
}

func BenchmarkKVPut(b *testing.B) {
	ctx := context.Background()
	kv := createTestingKV(b, 3, 2, 3)
	data := frand.Bytes(renterhost.SectorSize * 2)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		err := kv.PutBytes(ctx, []byte("foo"), data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKVGet(b *testing.B) {
	ctx := context.Background()
	kv := createTestingKV(b, 3, 2, 3)
	data := frand.Bytes(renterhost.SectorSize * 2)
	err := kv.PutBytes(ctx, []byte("foo"), data)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		err := kv.Get(ctx, []byte("foo"), ioutil.Discard)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKVPutParallel(b *testing.B) {
	ctx := context.Background()
	kv := createTestingKV(b, 3, 2, 3)
	data := frand.Bytes(renterhost.SectorSize * 2)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	const p = 4
	errCh := make(chan error, p)
	for j := 0; j < p; j++ {
		go func() {
			var err error
			for i := 0; i < b.N/p; i++ {
				err = kv.PutBytes(ctx, []byte("foo"), data)
				if err != nil {
					break
				}
			}
			errCh <- err
		}()
	}
	for j := 0; j < p; j++ {
		if err := <-errCh; err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKVGetParallel(b *testing.B) {
	ctx := context.Background()
	kv := createTestingKV(b, 3, 2, 3)
	data := frand.Bytes(renterhost.SectorSize * 2)
	err := kv.PutBytes(ctx, []byte("foo"), data)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	const p = 4
	errCh := make(chan error, p)
	for j := 0; j < p; j++ {
		go func() {
			var err error
			for i := 0; i < b.N/p; i++ {
				err = kv.Get(ctx, []byte("foo"), ioutil.Discard)
				if err != nil {
					break
				}
			}
			errCh <- err
		}()
	}
	for j := 0; j < p; j++ {
		if err := <-errCh; err != nil {
			b.Fatal(err)
		}
	}
}
