package main

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
)

type mockCS struct {
	subscriber modules.ConsensusSetSubscriber
}

func (m *mockCS) ConsensusSetSubscribe(s modules.ConsensusSetSubscriber, ccid modules.ConsensusChangeID, cancel <-chan struct{}) error {
	m.subscriber = s
	// send genesis block
	m.subscriber.ProcessConsensusChange(modules.ConsensusChange{
		AppliedBlocks: []types.Block{types.GenesisBlock},
		ID:            modules.ConsensusChangeID(crypto.HashBytes(fastrand.Bytes(12))),
	})
	return nil
}

func (m *mockCS) Synced() bool { return true }

func (m *mockCS) sendHostAnnouncement(ann []byte) {
	m.subscriber.ProcessConsensusChange(modules.ConsensusChange{
		AppliedBlocks: []types.Block{{
			Transactions: []types.Transaction{{
				ArbitraryData: [][]byte{ann},
			}},
		}},
		ID: modules.ConsensusChangeID(crypto.HashBytes(fastrand.Bytes(12))),
	})
}

type memPersist struct {
	shardPersist
}

func (p *memPersist) save(data shardPersist) error {
	p.shardPersist = data
	return nil
}

func (p *memPersist) load(data *shardPersist) error {
	*data = p.shardPersist
	return nil
}

func httpGet(h http.Handler, route string) ([]byte, error) {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", route, nil))
	r := rec.Result()
	body, _ := ioutil.ReadAll(r.Body)
	if r.StatusCode != 200 {
		return nil, errors.New(string(body))
	}
	return body, nil
}

func getSynced(h http.Handler) (bool, error) {
	resp, err := httpGet(h, "/synced")
	if err != nil {
		return false, err
	}
	return strconv.ParseBool(string(resp))
}

func getHeight(h http.Handler) (types.BlockHeight, error) {
	resp, err := httpGet(h, "/height")
	if err != nil {
		return 0, err
	}
	height, err := strconv.Atoi(string(resp))
	return types.BlockHeight(height), err
}

func getHost(h http.Handler, spk types.SiaPublicKey) ([]byte, error) {
	return httpGet(h, "/host/"+spk.String())
}

func TestServer(t *testing.T) {
	cs := new(mockCS)
	p := new(memPersist)
	shard, err := newSHARD(cs, p)
	if err != nil {
		t.Fatal(err)
	}
	ss := newServer(shard)

	// synced should be true
	if synced, err := getSynced(ss); err != nil {
		t.Fatal(err)
	} else if !synced {
		t.Fatal("should be synced")
	}

	// initial height should be zero
	if height, err := getHeight(ss); err != nil {
		t.Fatal(err)
	} else if height != 0 {
		t.Fatal("height should be 0, got", height)
	}

	// add a host
	addr := modules.NetAddress("1.1.1.1:1")
	sk, pk := crypto.GenerateKeyPair()
	spk := types.Ed25519PublicKey(pk)
	ann, err := modules.CreateAnnouncement(addr, spk, sk)
	if err != nil {
		t.Fatal(err)
	}
	cs.sendHostAnnouncement(ann)

	// height should now be 1, and host should be present
	if height, err := getHeight(ss); err != nil {
		t.Fatal(err)
	} else if height != 1 {
		t.Fatal("height should be 1, got", height)
	}
	annResp, err := getHost(ss, spk)
	if err != nil {
		t.Fatal(err)
	}
	daddr, dpk, err := modules.DecodeAnnouncement(annResp)
	if err != nil {
		t.Fatal(err)
	}
	if daddr != addr {
		t.Fatal("wrong address")
	} else if dpk.String() != spk.String() {
		t.Fatal("wrong pubkey")
	}
}

func TestServerThreadSafety(t *testing.T) {
	cs := new(mockCS)
	p := new(memPersist)
	shard, err := newSHARD(cs, p)
	if err != nil {
		t.Fatal(err)
	}
	ss := newServer(shard)

	// generate announcements from 3 hosts, ensuring overlap
	sks := make([]crypto.SecretKey, 3)
	for i := range sks {
		sk, _ := crypto.GenerateKeyPair()
		sks[i] = sk
	}
	newAnnouncement := func() []byte {
		addr := modules.NetAddress("1.1.1.1:1" + strconv.Itoa(fastrand.Intn(10)))
		sk := sks[fastrand.Intn(len(sks))]
		spk := types.Ed25519PublicKey(sk.PublicKey())
		ann, err := modules.CreateAnnouncement(addr, spk, sk)
		if err != nil {
			t.Fatal(err)
		}
		return ann
	}

	// concurrently call routes and add announcements
	funcs := []func(){
		func() { cs.sendHostAnnouncement(newAnnouncement()) },
		func() { getSynced(ss) },
		func() { getHeight(ss) },
		func() { getHost(ss, types.Ed25519PublicKey(sks[fastrand.Intn(len(sks))].PublicKey())) },
	}
	var wg sync.WaitGroup
	wg.Add(len(funcs))
	for _, fn := range funcs {
		go func(fn func()) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				time.Sleep(time.Duration(fastrand.Intn(10)) * time.Millisecond)
				fn()
			}
		}(fn)
	}
	wg.Wait()
}

func BenchmarkServer(b *testing.B) {
	cs := new(mockCS)
	p := new(memPersist)
	shard, err := newSHARD(cs, p)
	if err != nil {
		b.Fatal(err)
	}
	ss := newServer(shard)

	// add a host
	addr := modules.NetAddress("1.1.1.1:1")
	sk, pk := crypto.GenerateKeyPair()
	spk := types.Ed25519PublicKey(pk)
	ann, err := modules.CreateAnnouncement(addr, spk, sk)
	if err != nil {
		b.Fatal(err)
	}
	cs.sendHostAnnouncement(ann)

	b.ResetTimer()
	b.Run("synced", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			getSynced(ss)
		}
	})
	b.Run("height", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			getHeight(ss)
		}
	})
	b.Run("host", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			getHost(ss, spk)
		}
	})
}
