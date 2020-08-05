package renterutil

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/encoding"
	"gitlab.com/NebulousLabs/bolt"
	"golang.org/x/crypto/blake2b"
	"lukechampine.com/frand"
	"lukechampine.com/us/hostdb"
	"lukechampine.com/us/renter"
)

// ErrKeyNotFound is returned when a key is not found in a MetaDB.
var ErrKeyNotFound = errors.New("key not found")

// A DBBlob is the concatenation of one or more chunks.
type DBBlob struct {
	Key    []byte
	Chunks []uint64
}

// A DBChunk is a set of erasure-encoded shards.
type DBChunk struct {
	ID        uint64
	Shards    []uint64
	MinShards uint8
	Len       uint64 // of chunk, before erasure encoding
}

// A DBShard is a piece of data stored on a Sia host.
type DBShard struct {
	HostKey    hostdb.HostPublicKey
	SectorRoot crypto.Hash
	Offset     uint32
	// NOTE: Length is not stored, as it can be derived from the DBChunk.Len
}

// A DBSeed contains entropy that can be used to derive encryption keys and
// nonces.
type DBSeed [32]byte

// KeySeed derives an encryption key from the seed and chunk ID.
func (s *DBSeed) KeySeed(chunk uint64) (key renter.KeySeed) {
	buf := make([]byte, 7+32+8)
	n := copy(buf, "keyseed")
	n += copy(buf[n:], s[:])
	binary.LittleEndian.PutUint64(buf[n:], chunk)
	h := blake2b.Sum256(buf)
	copy(key[:], h[:])
	return
}

// Nonce derives an encryption nonce from the seed, chunk ID, and shard index.
func (s *DBSeed) Nonce(chunk uint64, shard int) (nonce [24]byte) {
	buf := make([]byte, 5+32+8+8)
	n := copy(buf, "nonce")
	n += copy(buf[n:], s[:])
	binary.LittleEndian.PutUint64(buf[n:], chunk)
	n += 8
	binary.LittleEndian.PutUint64(buf[n:], uint64(shard))
	h := blake2b.Sum256(buf)
	copy(nonce[:], h[:])
	return
}

// A MetaDB stores the metadata of blobs stored on Sia hosts.
type MetaDB interface {
	AddBlob(b DBBlob) error
	Blob(key []byte) (DBBlob, error)
	DeleteBlob(key []byte) error

	AddChunk(c DBChunk) (uint64, error)
	Chunk(id uint64) (DBChunk, error)

	AddShard(s DBShard) (uint64, error)
	Shard(id uint64) (DBShard, error)

	UnreferencedSectors() (map[hostdb.HostPublicKey][]crypto.Hash, error)

	// The entropy must be the same across calls.
	Seed() *DBSeed

	Close() error
}

// EphemeralMetaDB implements MetaDB in memory.
type EphemeralMetaDB struct {
	shards []DBShard
	chunks []DBChunk
	blobs  map[string]DBBlob
	refs   map[uint64]int
	seed   DBSeed
	mu     sync.Mutex
}

// Seed implements MetaDB.
func (db *EphemeralMetaDB) Seed() *DBSeed {
	return &db.seed
}

// AddShard implements MetaDB.
func (db *EphemeralMetaDB) AddShard(s DBShard) (uint64, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.shards = append(db.shards, s)
	return uint64(len(db.shards)), nil
}

// Shard implements MetaDB.
func (db *EphemeralMetaDB) Shard(id uint64) (DBShard, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.shards[id-1], nil
}

// AddChunk implements MetaDB.
func (db *EphemeralMetaDB) AddChunk(c DBChunk) (uint64, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if c.ID == 0 {
		c.ID = uint64(len(db.chunks)) + 1
		db.chunks = append(db.chunks, c)
	} else {
		// update refcounts
		for _, sid := range db.chunks[c.ID-1].Shards {
			if sid != 0 {
				db.refs[sid]--
			}
		}
		for _, sid := range c.Shards {
			if sid != 0 {
				db.refs[sid]++
			}
		}
		db.chunks[c.ID-1] = c
	}
	return c.ID, nil
}

// Chunk implements MetaDB.
func (db *EphemeralMetaDB) Chunk(id uint64) (DBChunk, error) {
	if id == 0 {
		panic("GetChunk: unset id")
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.chunks[id-1], nil
}

// AddBlob implements MetaDB.
func (db *EphemeralMetaDB) AddBlob(b DBBlob) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.blobs[string(b.Key)] = b
	return nil
}

// Blob implements MetaDB.
func (db *EphemeralMetaDB) Blob(key []byte) (DBBlob, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	b, ok := db.blobs[string(key)]
	if !ok {
		return DBBlob{}, ErrKeyNotFound
	}
	return b, nil
}

// DeleteBlob implements MetaDB.
func (db *EphemeralMetaDB) DeleteBlob(key []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	b, ok := db.blobs[string(key)]
	if !ok {
		return nil
	}
	for _, cid := range b.Chunks {
		for _, sid := range db.chunks[cid-1].Shards {
			db.refs[sid]--
		}
	}
	delete(db.blobs, string(key))
	return nil
}

// UnreferencedSectors returns all sectors that are not referenced by any blob
// in the db.
func (db *EphemeralMetaDB) UnreferencedSectors() (map[hostdb.HostPublicKey][]crypto.Hash, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	m := make(map[hostdb.HostPublicKey][]crypto.Hash)
	for sid, n := range db.refs {
		if n == 0 {
			s := db.shards[sid-1]
			m[s.HostKey] = append(m[s.HostKey], s.SectorRoot)
		}
	}
	return m, nil
}

// Close implements MetaDB.
func (db *EphemeralMetaDB) Close() error {
	return nil
}

// NewEphemeralMetaDB initializes an EphemeralMetaDB.
func NewEphemeralMetaDB() *EphemeralMetaDB {
	db := &EphemeralMetaDB{
		refs:  make(map[uint64]int),
		blobs: make(map[string]DBBlob),
	}
	frand.Read(db.seed[:])
	return db
}

// BoltMetaDB implements MetaDB with a Bolt database.
type BoltMetaDB struct {
	bdb  *bolt.DB
	seed DBSeed
}

var (
	bucketMeta   = []byte("meta")
	keySeed      = []byte("seed")
	bucketBlobs  = []byte("blobs")
	bucketChunks = []byte("chunks")
	bucketShards = []byte("shards")
)

// Seed implements MetaDB.
func (db *BoltMetaDB) Seed() *DBSeed {
	return &db.seed
}

// AddShard implements MetaDB.
func (db *BoltMetaDB) AddShard(s DBShard) (id uint64, err error) {
	err = db.bdb.Update(func(tx *bolt.Tx) error {
		id, err = tx.Bucket(bucketChunks).NextSequence()
		if err != nil {
			return err
		}
		key := make([]byte, 8)
		binary.LittleEndian.PutUint64(key, id)
		return tx.Bucket(bucketShards).Put(key, encoding.Marshal(s))
	})
	return
}

// Shard implements MetaDB.
func (db *BoltMetaDB) Shard(id uint64) (s DBShard, err error) {
	key := make([]byte, 8)
	binary.LittleEndian.PutUint64(key, id)
	err = db.bdb.View(func(tx *bolt.Tx) error {
		return encoding.Unmarshal(tx.Bucket(bucketShards).Get(key), &s)
	})
	return
}

// AddChunk implements MetaDB.
func (db *BoltMetaDB) AddChunk(c DBChunk) (id uint64, err error) {
	err = db.bdb.Update(func(tx *bolt.Tx) error {
		if c.ID == 0 {
			c.ID, err = tx.Bucket(bucketChunks).NextSequence()
			if err != nil {
				return err
			}
		}
		key := make([]byte, 8)
		binary.LittleEndian.PutUint64(key, c.ID)
		return tx.Bucket(bucketChunks).Put(key, encoding.Marshal(c))
	})
	return c.ID, err
}

// Chunk implements MetaDB.
func (db *BoltMetaDB) Chunk(id uint64) (c DBChunk, err error) {
	key := make([]byte, 8)
	binary.LittleEndian.PutUint64(key, id)
	err = db.bdb.View(func(tx *bolt.Tx) error {
		return encoding.Unmarshal(tx.Bucket(bucketChunks).Get(key), &c)
	})
	return
}

// AddBlob implements MetaDB.
func (db *BoltMetaDB) AddBlob(b DBBlob) error {
	return db.bdb.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketBlobs).Put(b.Key, encoding.Marshal(b.Chunks))
	})
}

// Blob implements MetaDB.
func (db *BoltMetaDB) Blob(key []byte) (b DBBlob, err error) {
	err = db.bdb.View(func(tx *bolt.Tx) error {
		blobBytes := tx.Bucket(bucketBlobs).Get(key)
		if len(blobBytes) == 0 {
			return ErrKeyNotFound
		}
		return encoding.Unmarshal(blobBytes, &b.Chunks)
	})
	b.Key = key
	return
}

// DeleteBlob implements MetaDB.
func (db *BoltMetaDB) DeleteBlob(key []byte) error {
	return db.bdb.Update(func(tx *bolt.Tx) error {
		// TODO: refcounts
		return tx.Bucket(bucketBlobs).Delete(key)
	})
}

// UnreferencedSectors returns all sectors that are not referenced by any blob
// in the db.
func (db *BoltMetaDB) UnreferencedSectors() (map[hostdb.HostPublicKey][]crypto.Hash, error) {
	return nil, nil // TODO
}

// Close implements MetaDB.
func (db *BoltMetaDB) Close() error {
	return db.bdb.Close()
}

// NewBoltMetaDB initializes a MetaDB backed by a Bolt database.
func NewBoltMetaDB(path string) (*BoltMetaDB, error) {
	bdb, err := bolt.Open(path, 0660, &bolt.Options{
		Timeout: 3 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	db := &BoltMetaDB{
		bdb: bdb,
	}
	// initialize
	err = bdb.Update(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{
			bucketMeta,
			bucketBlobs,
			bucketChunks,
			bucketShards,
		} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		bm := tx.Bucket(bucketMeta)
		if bm.Get(keySeed) == nil {
			bm.Put(keySeed, frand.Bytes(32))
		}
		copy(db.seed[:], bm.Get(keySeed))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return db, nil
}
