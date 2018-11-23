package wallet

import (
	"bytes"
	"encoding/binary"
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

	// bucketOutputs maps SiacoinOutputIDs to UnspentOutputs.
	bucketOutputs = []byte("bucketOutputs")

	// bucketLimboOutputs maps SiacoinOutputIDs to UnspentOutputs.
	bucketLimboOutputs = []byte("bucketLimboOutputs")

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
		bucketLimboOutputs,
		bucketTxns,
		bucketTxnsAddrIndex,
		bucketTxnsRecentIndex,
	}
)

// BoltDBStore implements SeedStore and WatchOnlyStore with a Bolt key-value
// database.
type BoltDBStore struct {
	db    *bolt.DB
	addrs map[types.UnlockHash]struct{}
}

// ApplyConsensusChange implements Store.
func (s *BoltDBStore) ApplyConsensusChange(reverted, applied ProcessedConsensusChange, ccid modules.ConsensusChangeID) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, o := range reverted.Outputs {
			tx.Bucket(bucketOutputs).Delete(o.ID[:])
			tx.Bucket(bucketLimboOutputs).Delete(o.ID[:])
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
			tx.Bucket(bucketOutputs).Put(o.ID[:], encoding.Marshal(o))
			tx.Bucket(bucketLimboOutputs).Delete(o.ID[:])
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
	s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketOutputs).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var o UnspentOutput
			encoding.Unmarshal(v, &o)
			outputs = append(outputs, o)
		}
		return nil
	})
	return
}

// LimboOutputs implements Store.
func (s *BoltDBStore) LimboOutputs() (outputs []UnspentOutput) {
	s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketLimboOutputs).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var o UnspentOutput
			encoding.Unmarshal(v, &o)
			outputs = append(outputs, o)
		}
		return nil
	})
	return
}

// Transactions implements Store.
func (s *BoltDBStore) Transactions(n int) (txids []types.TransactionID) {
	s.db.View(func(tx *bolt.Tx) error {
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
	s.db.View(func(tx *bolt.Tx) error {
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
	s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketTxns).Get(id[:]); v != nil {
			encoding.Unmarshal(v, &txn)
			exists = true
		}
		return nil
	})
	return
}

// MarkSpent implements Store.
func (s *BoltDBStore) MarkSpent(id types.SiacoinOutputID, spent bool) {
	s.db.Update(func(tx *bolt.Tx) error {
		if spent {
			v := tx.Bucket(bucketOutputs).Get(id[:])
			if v != nil {
				tx.Bucket(bucketLimboOutputs).Put(id[:], v)
				tx.Bucket(bucketOutputs).Delete(id[:])
			}
		} else {
			v := tx.Bucket(bucketLimboOutputs).Get(id[:])
			if v != nil {
				tx.Bucket(bucketOutputs).Put(id[:], v)
				tx.Bucket(bucketLimboOutputs).Delete(id[:])
			}
		}
		return nil
	})
}

// ChainHeight implements Store.
func (s *BoltDBStore) ChainHeight() (height types.BlockHeight) {
	s.db.View(func(tx *bolt.Tx) error {
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
	s.db.View(func(tx *bolt.Tx) error {
		copy(ccid[:], tx.Bucket(bucketMeta).Get(keyCCID))
		return nil
	})
	return
}

// SeedIndex implements SeedStore.
func (s *BoltDBStore) SeedIndex() (index uint64) {
	s.db.View(func(tx *bolt.Tx) error {
		index = binary.LittleEndian.Uint64(tx.Bucket(bucketMeta).Get(keySeedIndex))
		return nil
	})
	return
}

// SetSeedIndex implements SeedStore.
func (s *BoltDBStore) SetSeedIndex(index uint64) {
	s.db.Update(func(tx *bolt.Tx) error {
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
	s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAddrs).Put(addr[:], append([]byte(nil), info...))
	})
	s.addrs[addr] = struct{}{}
}

// AddressInfo implements WatchOnlyStore.
func (s *BoltDBStore) AddressInfo(addr types.UnlockHash) (info []byte) {
	s.db.View(func(tx *bolt.Tx) error {
		info = append(info, tx.Bucket(bucketAddrs).Get(addr[:])...)
		return nil
	})
	return
}

// RemoveAddress implements WatchOnlyStore.
func (s *BoltDBStore) RemoveAddress(addr types.UnlockHash) {
	s.db.Update(func(tx *bolt.Tx) error {
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

// Close closes the bolt database.
func (s *BoltDBStore) Close() error {
	return s.db.Close()
}

// NewBoltDBStore returns a new BoltDBStore.
func NewBoltDBStore(filename string) (*BoltDBStore, error) {
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
	}, nil
}
