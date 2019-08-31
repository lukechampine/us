package wallet

import (
	"bytes"
	"encoding/binary"
	"os"
	"time"

	"gitlab.com/NebulousLabs/Sia/encoding"
	"gitlab.com/NebulousLabs/Sia/modules"
	"gitlab.com/NebulousLabs/Sia/types"
	bolt "go.etcd.io/bbolt"
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

	// bucketBlockRewards contains a list of BlockRewards, sorted by insertion date.
	bucketBlockRewards = []byte("bucketBlockRewards")

	// bucketFileContracts contains a list of FileContracts, sorted by insertion date.
	bucketFileContracts = []byte("bucketFileContracts")

	// bucketMemos maps TransactionIDs to memos.
	bucketMemos = []byte("bucketMemos")

	// bucketTxns maps TransactionIDs to Transactions.
	bucketTxns = []byte("bucketTxns")

	// bucketTxnsAddrIndex maps UnlockHashes to a bucket of TransactionIDs.
	bucketTxnsAddrIndex = []byte("bucketTxnsAddrIndex")

	// bucketTxnsRecentIndex contains a list of TransactionIDs, sorted by insertion date.
	bucketTxnsRecentIndex = []byte("bucketTxnsRecentIndex")

	// bucketLimbo maps TransactionIDs to LimboTransactions.
	bucketLimbo = []byte("bucketLimbo")

	dbBuckets = [][]byte{
		bucketAddrs,
		bucketBlockRewards,
		bucketFileContracts,
		bucketLimbo,
		bucketMemos,
		bucketMeta,
		bucketOutputs,
		bucketTxns,
		bucketTxnsAddrIndex,
		bucketTxnsRecentIndex,
	}
)

// BoltDBStore implements Store with a Bolt key-value database.
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
		if len(reverted.BlockRewards) > 0 {
			for i := range reverted.BlockRewards {
				c := tx.Bucket(bucketBlockRewards).Cursor()
				for k, v := c.Last(); k != nil; k, v = c.Prev() {
					var br BlockReward
					encoding.Unmarshal(v, &br)
					if br.ID == reverted.BlockRewards[i].ID {
						tx.Bucket(bucketBlockRewards).Delete(k)
						break
					}
				}
			}
		}
		if len(reverted.FileContracts) > 0 {
			for i := range reverted.FileContracts {
				c := tx.Bucket(bucketFileContracts).Cursor()
				for k, v := c.Last(); k != nil; k, v = c.Prev() {
					var fc FileContract
					encoding.Unmarshal(v, &fc)
					if fc.ID == reverted.FileContracts[i].ID && fc.RevisionNumber == reverted.FileContracts[i].RevisionNumber {
						tx.Bucket(bucketFileContracts).Delete(k)
						break
					}
				}
			}
		}

		for _, txn := range reverted.Transactions {
			txid := txn.ID()
			tx.Bucket(bucketTxns).Delete(txid[:])
			tx.Bucket(bucketLimbo).Delete(txid[:])
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

		// helper function for inserting value at next sequence number
		seqBytes := make([]byte, 8)
		putSeq := func(b *bolt.Bucket, val []byte) error {
			seq, _ := tx.Bucket(bucketBlockRewards).NextSequence()
			binary.BigEndian.PutUint64(seqBytes, seq)
			return b.Put(seqBytes, val)
		}

		for _, o := range applied.Outputs {
			tx.Bucket(bucketOutputs).Put(o.ID[:], encoding.Marshal(o))
		}
		for _, br := range applied.BlockRewards {
			putSeq(tx.Bucket(bucketBlockRewards), encoding.Marshal(br))
		}
		for _, fc := range applied.FileContracts {
			putSeq(tx.Bucket(bucketFileContracts), encoding.Marshal(fc))
		}
		for _, txn := range applied.Transactions {
			txid := txn.ID()
			tx.Bucket(bucketTxns).Put(txid[:], encoding.Marshal(txn))
			tx.Bucket(bucketLimbo).Delete(txid[:])
			putSeq(tx.Bucket(bucketTxnsRecentIndex), txid[:])
		}
		for addr, txids := range applied.AddressTransactions {
			addrTxnsBucket, _ := tx.Bucket(bucketTxnsAddrIndex).CreateBucketIfNotExists(addr[:])
			for _, txid := range txids {
				putSeq(addrTxnsBucket, txid[:])
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
			var o UnspentOutput
			encoding.Unmarshal(v, &o)
			outputs = append(outputs, o)
		}
		return nil
	})
	return
}

// AddToLimbo implements Store.
func (s *BoltDBStore) AddToLimbo(txn types.Transaction) {
	s.update(func(tx *bolt.Tx) error {
		txid := txn.ID()
		if tx.Bucket(bucketLimbo).Get(txid[:]) != nil {
			return nil // don't overwrite older LimboSince
		}
		return tx.Bucket(bucketLimbo).Put(txid[:], encoding.Marshal(LimboTransaction{
			Transaction: txn,
			LimboSince:  time.Now(),
		}))
	})
	return
}

// RemoveFromLimbo implements Store.
func (s *BoltDBStore) RemoveFromLimbo(id types.TransactionID) {
	s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketLimbo).Delete(id[:])
	})
	return
}

// LimboTransactions implements Store.
func (s *BoltDBStore) LimboTransactions() (txns []LimboTransaction) {
	s.view(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketLimbo).Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var txn LimboTransaction
			encoding.Unmarshal(v, &txn)
			txns = append(txns, txn)
		}
		return nil
	})
	return
}

// BlockRewards implements Store.
func (s *BoltDBStore) BlockRewards(n int) (brs []BlockReward) {
	s.view(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketBlockRewards).Cursor()
		for k, v := c.Last(); k != nil && len(brs) != n; k, v = c.Prev() {
			var br BlockReward
			encoding.Unmarshal(v, &br)
			brs = append(brs, br)
		}
		return nil
	})
	return
}

// FileContracts implements Store.
func (s *BoltDBStore) FileContracts(n int) (fcs []FileContract) {
	s.view(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketFileContracts).Cursor()
		for k, v := c.Last(); k != nil && len(fcs) != n; k, v = c.Prev() {
			var fc FileContract
			encoding.Unmarshal(v, &fc)
			fcs = append(fcs, fc)
		}
		return nil
	})
	return
}

// FileContractHistory implements Store.
func (s *BoltDBStore) FileContractHistory(id types.FileContractID) (history []FileContract) {
	s.view(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketFileContracts).Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var fc FileContract
			encoding.Unmarshal(v, &fc)
			if fc.ID == id {
				history = append(history, fc)
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
func (s *BoltDBStore) Transaction(id types.TransactionID) (txn Transaction, exists bool) {
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

// SeedIndex implements Store.
func (s *BoltDBStore) SeedIndex() (index uint64) {
	s.view(func(tx *bolt.Tx) error {
		index = binary.LittleEndian.Uint64(tx.Bucket(bucketMeta).Get(keySeedIndex))
		return nil
	})
	return
}

// SetSeedIndex implements Store.
func (s *BoltDBStore) SetSeedIndex(index uint64) {
	s.update(func(tx *bolt.Tx) error {
		indexBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(indexBytes, index)
		tx.Bucket(bucketMeta).Put(keySeedIndex, indexBytes)
		return nil
	})
}

// OwnsAddress implements Store.
func (s *BoltDBStore) OwnsAddress(addr types.UnlockHash) (owned bool) {
	_, ok := s.addrs[addr]
	return ok
}

// AddAddress implements Store.
func (s *BoltDBStore) AddAddress(info SeedAddressInfo) {
	addr := CalculateUnlockHash(info.UnlockConditions)
	s.update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketAddrs).Put(addr[:], encoding.Marshal(info)); err != nil {
			return err
		}

		// update seedIndex
		//
		// NOTE: this algorithm will skip certain indices if they are inserted
		// out-of-order. However, it runs in constant time and it will never
		// mistakenly reuse an index. The trade-off seems worth it.
		index := binary.LittleEndian.Uint64(tx.Bucket(bucketMeta).Get(keySeedIndex))
		if next := info.KeyIndex + 1; index < next {
			index = next
		}
		indexBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(indexBytes, index)
		return tx.Bucket(bucketMeta).Put(keySeedIndex, indexBytes)
	})
	s.addrs[addr] = struct{}{}
}

// AddressInfo implements Store.
func (s *BoltDBStore) AddressInfo(addr types.UnlockHash) (info SeedAddressInfo, exists bool) {
	s.view(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketAddrs).Get(addr[:]); v != nil {
			encoding.Unmarshal(v, &info)
			exists = true
		}
		return nil
	})
	return
}

// RemoveAddress implements Store.
func (s *BoltDBStore) RemoveAddress(addr types.UnlockHash) {
	s.update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAddrs).Delete(addr[:])
	})
	delete(s.addrs, addr)
}

// Addresses implements Store.
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
