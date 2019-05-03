package wallet

import (
	"bytes"
	"encoding/binary"
	"os"
	"time"

	bolt "github.com/coreos/bbolt"
	"gitlab.com/NebulousLabs/Sia/encoding"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
)

// database buckets/keys
var (
	// keyHeight stores the current chain height.
	keyHeight = []byte("keyHeight")

	// keyCCID stores the current ConsensusChangeID.
	keyCCID = []byte("keyCCID")

	// keySeedIndex stores the current seed index.
	keySeedIndex = []byte("keySeedIndex")

	// bucketMeta contains global values for the db.
	bucketMeta = []byte("bucketMeta")

	// bucketAddrs stores the set of watched addresses.
	bucketAddrs = []byte("bucketAddrs")

	// bucketOutputs maps SiacoinOutputIDs to LimboOutputs. If an output is not
	// in limbo, its LimboSince is set to notLimboTime.
	bucketOutputs = []byte("bucketOutputs")

	// bucketMemos maps TransactionIDs to memos.
	bucketMemos = []byte("bucketMemos")

	// bucketTxns maps TransactionIDs to Transactions.
	bucketTxns = []byte("bucketTxns")

	// bucketTxnsAddrIndex maps UnlockHashes to a bucket of TransactionIDs.
	bucketTxnsAddrIndex = []byte("bucketTxnsAddrIndex")

	// bucketTxnsRecentIndex contains a list of TransactionIDs, sorted by insertion date.
	bucketTxnsRecentIndex = []byte("bucketTxnsRecentIndex")

	dbBuckets = [][]byte{
		bucketMeta,
		bucketAddrs,
		bucketOutputs,
		bucketMemos,
		bucketTxns,
		bucketTxnsAddrIndex,
		bucketTxnsRecentIndex,
	}
)

// notLimboTime is a sentinel value for outputs that are not in limbo.
var notLimboTime = time.Time{}

// BoltDBStore implements SeedStore and WatchOnlyStore with a Bolt key-value
// database.
type BoltDBStore struct {
	db    *bolt.DB
	addrs map[types.UnlockHash]struct{}
	onErr func(error)
}

func (s *BoltDBStore) view(fn func(*bolt.Tx) error) {
	err := s.db.View(fn)
	if err != nil {
		s.onErr(err)
	}
}

func (s *BoltDBStore) update(fn func(*bolt.Tx) error) {
	err := s.db.Update(fn)
	if err != nil {
		s.onErr(err)
	}
}

// ApplyConsensusChange implements Store.
func (s *BoltDBStore) ApplyConsensusChange(reverted, applied ProcessedConsensusChange, ccid modules.ConsensusChangeID) {
	s.update(func(tx *bolt.Tx) error {
		for _, o := range reverted.Outputs {
			tx.Bucket(bucketOutputs).Delete(o.ID[:])
		}
		for _, txn := range reverted.Transactions {
			txid := txn.ID()
			tx.Bucket(bucketTxns).Delete(txid[:])
			c := tx.Bucket(bucketTxnsRecentIndex).Cursor()
			for k, v := c.Last(); k != nil; k, v = c.Prev() {
				if bytes.Equal(v, txid[:]) {
					tx.Bucket(bucketTxnsRecentIndex).Delete(k)
					break
				}
			}
		}
		for addr, txids := range reverted.AddressTransactions {
			addrTxnsBucket := tx.Bucket(bucketTxnsAddrIndex).Bucket(addr[:])
			if addrTxnsBucket == nil {
				continue
			}
			c := addrTxnsBucket.Cursor()
			for k, v := c.Last(); k != nil; k, v = c.Prev() {
				for _, txid := range txids {
					if bytes.Equal(v, txid[:]) {
						addrTxnsBucket.Delete(k)
						break
					}
				}
			}
		}

		for _, o := range applied.Outputs {
			lo := LimboOutput{UnspentOutput: o, LimboSince: notLimboTime}
			tx.Bucket(bucketOutputs).Put(o.ID[:], encoding.Marshal(lo))
		}
		for _, txn := range applied.Transactions {
			txid := txn.ID()
			tx.Bucket(bucketTxns).Put(txid[:], encoding.Marshal(txn))
			seq, _ := tx.Bucket(bucketTxnsRecentIndex).NextSequence()
			seqBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(seqBytes, seq)
			tx.Bucket(bucketTxnsRecentIndex).Put(seqBytes, txid[:])
		}
		for addr, txids := range applied.AddressTransactions {
			addrTxnsBucket, _ := tx.Bucket(bucketTxnsAddrIndex).CreateBucketIfNotExists(addr[:])
			seq, _ := addrTxnsBucket.NextSequence()
			seqBytes := make([]byte, 8)
			for _, txid := range txids {
				binary.BigEndian.PutUint64(seqBytes, seq)
				addrTxnsBucket.Put(seqBytes, txid[:])
				seq++
			}
		}

		heightBytes := append([]byte(nil), tx.Bucket(bucketMeta).Get(keyHeight)...)
		height := binary.LittleEndian.Uint64(heightBytes) + uint64(applied.BlockCount) - uint64(reverted.BlockCount)
		binary.LittleEndian.PutUint64(heightBytes, height)
		tx.Bucket(bucketMeta).Put(keyHeight, heightBytes)

		tx.Bucket(bucketMeta).Put(keyCCID, ccid[:])
		return nil
	})
}

// UnspentOutputs implements Store.
func (s *BoltDBStore) UnspentOutputs() (outputs []UnspentOutput) {
	s.view(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketOutputs).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var o LimboOutput
			encoding.Unmarshal(v, &o)
			if o.LimboSince.Equal(notLimboTime) {
				outputs = append(outputs, o.UnspentOutput)
			}
		}
		return nil
	})
	return
}

// LimboOutputs implements Store.
func (s *BoltDBStore) LimboOutputs() (outputs []LimboOutput) {
	s.view(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketOutputs).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var o LimboOutput
			encoding.Unmarshal(v, &o)
			if !o.LimboSince.Equal(notLimboTime) {
				outputs = append(outputs, o)
			}
		}
		return nil
	})
	return
}

// Transactions implements Store.
func (s *BoltDBStore) Transactions(n int) (txids []types.TransactionID) {
	s.view(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketTxnsRecentIndex).Cursor()
		for k, v := c.Last(); k != nil && len(txids) != n; k, v = c.Prev() {
			var txid types.TransactionID
			copy(txid[:], v)
			txids = append(txids, txid)
		}
		return nil
	})
	return
}

// TransactionsByAddress implements Store.
func (s *BoltDBStore) TransactionsByAddress(addr types.UnlockHash, n int) (txids []types.TransactionID) {
	s.view(func(tx *bolt.Tx) error {
		addrTxnsBucket := tx.Bucket(bucketTxnsAddrIndex).Bucket(addr[:])
		if addrTxnsBucket == nil {
			return nil
		}
		c := addrTxnsBucket.Cursor()
		for k, v := c.Last(); k != nil && len(txids) != n; k, v = c.Prev() {
			var txid types.TransactionID
			copy(txid[:], v)
			txids = append(txids, txid)
		}
		return nil
	})
	return
}

// Transaction implements Store.
func (s *BoltDBStore) Transaction(id types.TransactionID) (txn types.Transaction, exists bool) {
	s.view(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketTxns).Get(id[:]); v != nil {
			encoding.Unmarshal(v, &txn)
			exists = true
		}
		return nil
	})
	return
}

// SetMemo implements Store.
func (s *BoltDBStore) SetMemo(txid types.TransactionID, memo []byte) {
	s.update(func(tx *bolt.Tx) error {
		tx.Bucket(bucketMemos).Put(txid[:], append([]byte(nil), memo...))
		return nil
	})
}

// Memo implements Store.
func (s *BoltDBStore) Memo(txid types.TransactionID) (memo []byte) {
	s.view(func(tx *bolt.Tx) error {
		memo = append([]byte(nil), tx.Bucket(bucketMemos).Get(txid[:])...)
		return nil
	})
	return
}

// MarkSpent implements Store.
func (s *BoltDBStore) MarkSpent(id types.SiacoinOutputID, spent bool) {
	s.update(func(tx *bolt.Tx) error {
		v := append([]byte(nil), tx.Bucket(bucketOutputs).Get(id[:])...)
		if len(v) == 0 {
			return nil
		}
		var since time.Time
		if spent {
			since = time.Now()
		} else {
			since = notLimboTime
		}
		binary.LittleEndian.PutUint64(v[len(v)-8:], uint64(since.Unix()))
		tx.Bucket(bucketOutputs).Put(id[:], v)
		return nil
	})
}

// ChainHeight implements Store.
func (s *BoltDBStore) ChainHeight() (height types.BlockHeight) {
	s.view(func(tx *bolt.Tx) error {
		height = types.BlockHeight(binary.LittleEndian.Uint64(tx.Bucket(bucketMeta).Get(keyHeight)))
		if height > 0 {
			height-- // adjust for genesis block
		}
		return nil
	})
	return
}

// ConsensusChangeID implements Store.
func (s *BoltDBStore) ConsensusChangeID() (ccid modules.ConsensusChangeID) {
	s.view(func(tx *bolt.Tx) error {
		copy(ccid[:], tx.Bucket(bucketMeta).Get(keyCCID))
		return nil
	})
	return
}

// SeedIndex implements SeedStore.
func (s *BoltDBStore) SeedIndex() (index uint64) {
	s.view(func(tx *bolt.Tx) error {
		index = binary.LittleEndian.Uint64(tx.Bucket(bucketMeta).Get(keySeedIndex))
		return nil
	})
	return
}

// SetSeedIndex implements SeedStore.
func (s *BoltDBStore) SetSeedIndex(index uint64) {
	s.update(func(tx *bolt.Tx) error {
		indexBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(indexBytes, index)
		tx.Bucket(bucketMeta).Put(keySeedIndex, indexBytes)
		return nil
	})
}

// OwnsAddress implements WatchOnlyStore.
func (s *BoltDBStore) OwnsAddress(addr types.UnlockHash) (owned bool) {
	_, ok := s.addrs[addr]
	return ok
}

// AddAddress implements WatchOnlyStore.
func (s *BoltDBStore) AddAddress(addr types.UnlockHash, info []byte) {
	s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAddrs).Put(addr[:], append([]byte(nil), info...))
	})
	s.addrs[addr] = struct{}{}
}

// AddressInfo implements WatchOnlyStore.
func (s *BoltDBStore) AddressInfo(addr types.UnlockHash) (info []byte) {
	s.view(func(tx *bolt.Tx) error {
		info = append(info, tx.Bucket(bucketAddrs).Get(addr[:])...)
		return nil
	})
	return
}

// RemoveAddress implements WatchOnlyStore.
func (s *BoltDBStore) RemoveAddress(addr types.UnlockHash) {
	s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAddrs).Delete(addr[:])
	})
	delete(s.addrs, addr)
}

// Addresses implements WatchOnlyStore.
func (s *BoltDBStore) Addresses() []types.UnlockHash {
	addrs := make([]types.UnlockHash, 0, len(s.addrs))
	for addr := range s.addrs {
		addrs = append(addrs, addr)
	}
	return addrs
}

// Reset wipes the store's knowledge of the blockchain, including transactions,
// outputs, height, and consensus change ID. Addresses, memos, and the current
// seed index are preserved.
func (s *BoltDBStore) Reset() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		buckets := [][]byte{
			bucketOutputs,
			bucketTxns,
			bucketTxnsAddrIndex,
			bucketTxnsRecentIndex,
		}
		for _, b := range buckets {
			tx.DeleteBucket(b)
			tx.CreateBucket(b)
		}

		tx.Bucket(bucketMeta).Put(keyHeight, make([]byte, 8))
		tx.Bucket(bucketMeta).Put(keyCCID, modules.ConsensusChangeBeginning[:])
		return nil
	})
}

// Close closes the bolt database.
func (s *BoltDBStore) Close() error {
	return s.db.Close()
}

// NewBoltDBStore returns a new BoltDBStore. If onErr is nil, ExitOnError will
// be used.
func NewBoltDBStore(filename string, onErr func(error)) (*BoltDBStore, error) {
	if onErr == nil {
		onErr = ExitOnError
	}
	db, err := bolt.Open(filename, 0666, &bolt.Options{Timeout: 3 * time.Second})
	if err != nil {
		return nil, err
	}
	addrs := make(map[types.UnlockHash]struct{})
	err = db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range dbBuckets {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		if tx.Bucket(bucketMeta).Get(keyHeight) == nil {
			tx.Bucket(bucketMeta).Put(keyHeight, make([]byte, 8))
		}
		if tx.Bucket(bucketMeta).Get(keyCCID) == nil {
			tx.Bucket(bucketMeta).Put(keyCCID, modules.ConsensusChangeBeginning[:])
		}
		if tx.Bucket(bucketMeta).Get(keySeedIndex) == nil {
			tx.Bucket(bucketMeta).Put(keySeedIndex, make([]byte, 8))
		}
		// load addrs into memory for fast ownership checks
		c := tx.Bucket(bucketAddrs).Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			var addr types.UnlockHash
			copy(addr[:], k)
			addrs[addr] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &BoltDBStore{
		db:    db,
		addrs: addrs,
		onErr: onErr,
	}, nil
}

// ExitOnError prints err to stderr and exits with code 1.
func ExitOnError(err error) {
	os.Stderr.WriteString(err.Error())
	os.Exit(1)
}
