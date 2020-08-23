package host

import (
	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

// StorageManager ...
type StorageManager struct {
	store SectorStore
}

// ReadSection ...
func (sm *StorageManager) ReadSection(sec renterhost.RPCReadRequestSection, proof bool) (*renterhost.RPCReadResponse, error) {
	sector, err := sm.store.Sector(sec.MerkleRoot)
	if err != nil {
		return nil, err
	}
	resp := &renterhost.RPCReadResponse{
		Data: sector[sec.Offset:][:sec.Length],
	}
	if proof {
		proofStart := int(sec.Offset) / merkle.SegmentSize
		proofEnd := int(sec.Offset+sec.Length) / merkle.SegmentSize
		resp.MerkleProof = merkle.BuildProof(sector, proofStart, proofEnd, nil)
	}
	return resp, nil
}

// ReadSectors ...
func (sm *StorageManager) ReadSectors(id types.FileContractID, offset, length uint64) (*renterhost.RPCSectorRootsResponse, error) {
	roots, err := sm.store.ContractRoots(id)
	if err != nil {
		return nil, err
	}
	if offset > uint64(len(roots)) || offset+length > uint64(len(roots)) {
		return nil, errors.New("request is out-of-bounds")
	}
	return &renterhost.RPCSectorRootsResponse{
		SectorRoots: roots[offset:][:length],
		MerkleProof: merkle.BuildSectorRangeProof(roots, int(offset), int(offset+length)),
	}, nil
}

// ConsiderModifications ...
func (sm *StorageManager) ConsiderModifications(id types.FileContractID, actions []renterhost.RPCWriteAction, proof bool) (*renterhost.RPCWriteMerkleProof, error) {
	sectorRoots, err := sm.store.ContractRoots(id)
	if err != nil {
		return nil, err
	}
	newRoots := append([]crypto.Hash(nil), sectorRoots...)
	var sectorsRemoved []crypto.Hash
	gainedSectorData := make(map[crypto.Hash]*[renterhost.SectorSize]byte)
	for _, action := range actions {
		switch action.Type {
		case renterhost.RPCWriteActionAppend:
			var sector [renterhost.SectorSize]byte
			copy(sector[:], action.Data)
			newRoot := merkle.SectorRoot(&sector)
			newRoots = append(newRoots, newRoot)
			gainedSectorData[newRoot] = &sector

		case renterhost.RPCWriteActionTrim:
			numSectors := action.A
			sectorsRemoved = append(sectorsRemoved, newRoots[uint64(len(newRoots))-numSectors:]...)
			newRoots = newRoots[:uint64(len(newRoots))-numSectors]

		case renterhost.RPCWriteActionSwap:
			i, j := action.A, action.B
			newRoots[i], newRoots[j] = newRoots[j], newRoots[i]

		case renterhost.RPCWriteActionUpdate:
			sectorIndex, offset := action.A, action.B
			sector, err := sm.store.Sector(newRoots[sectorIndex])
			if err != nil {
				return nil, err
			}
			copy(sector[offset:], action.Data)
			newRoot := merkle.SectorRoot(sector)
			sectorsRemoved = append(sectorsRemoved, newRoots[sectorIndex])
			gainedSectorData[newRoot] = sector
			newRoots[sectorIndex] = newRoot
		}
	}
	merkleResp := &renterhost.RPCWriteMerkleProof{
		NewMerkleRoot: merkle.MetaRoot(newRoots),
	}
	if proof {
		merkleResp.OldSubtreeHashes, merkleResp.OldLeafHashes = merkle.BuildDiffProof(actions, sectorRoots)
	}
	return merkleResp, nil
}

// ApplyModifications ...
func (sm *StorageManager) ApplyModifications(id types.FileContractID, actions []renterhost.RPCWriteAction) error {
	sectorRoots, err := sm.store.ContractRoots(id)
	if err != nil {
		return err
	}
	newRoots := append([]crypto.Hash(nil), sectorRoots...)
	var sectorsRemoved []crypto.Hash
	gainedSectorData := make(map[crypto.Hash]*[renterhost.SectorSize]byte)
	for _, action := range actions {
		switch action.Type {
		case renterhost.RPCWriteActionAppend:
			var sector [renterhost.SectorSize]byte
			copy(sector[:], action.Data)
			newRoot := merkle.SectorRoot(&sector)
			newRoots = append(newRoots, newRoot)
			gainedSectorData[newRoot] = &sector

		case renterhost.RPCWriteActionTrim:
			numSectors := action.A
			sectorsRemoved = append(sectorsRemoved, newRoots[uint64(len(newRoots))-numSectors:]...)
			newRoots = newRoots[:uint64(len(newRoots))-numSectors]

		case renterhost.RPCWriteActionSwap:
			i, j := action.A, action.B
			newRoots[i], newRoots[j] = newRoots[j], newRoots[i]

		case renterhost.RPCWriteActionUpdate:
			sectorIndex, offset := action.A, action.B
			sector, err := sm.store.Sector(newRoots[sectorIndex])
			if err != nil {
				return err
			}
			copy(sector[offset:], action.Data)
			newRoot := merkle.SectorRoot(sector)
			sectorsRemoved = append(sectorsRemoved, newRoots[sectorIndex])
			gainedSectorData[newRoot] = sector
			newRoots[sectorIndex] = newRoot
		}
	}

	if err := sm.store.SetContractRoots(id, newRoots); err != nil {
		return err
	}
	for _, root := range sectorsRemoved {
		if err := sm.store.DeleteSector(root); err != nil {
			return err
		}
		delete(gainedSectorData, root)
	}
	for root, sector := range gainedSectorData {
		if err := sm.store.AddSector(root, sector); err != nil {
			return err
		}
	}
	return nil
}

// MoveContractRoots ...
func (sm *StorageManager) MoveContractRoots(from, to types.FileContractID) error {
	roots, err := sm.store.ContractRoots(from)
	if err != nil {
		return err
	} else if err := sm.store.SetContractRoots(to, roots); err != nil {
		return err
	} else if err := sm.store.SetContractRoots(from, nil); err != nil {
		return err
	}
	return nil
}

// BuildStorageProof ...
func (sm *StorageManager) BuildStorageProof(id types.FileContractID, index uint64) (types.StorageProof, error) {
	sectorIndex := int(index / merkle.SegmentsPerSector)
	segmentIndex := int(index % merkle.SegmentsPerSector)

	roots, err := sm.store.ContractRoots(id)
	if err != nil {
		return types.StorageProof{}, err
	}
	root := roots[sectorIndex]
	sector, err := sm.store.Sector(root)
	if err != nil {
		return types.StorageProof{}, err
	}
	segmentProof := merkle.ConvertProofOrdering(merkle.BuildProof(sector, segmentIndex, segmentIndex+1, nil), segmentIndex)
	sectorProof := merkle.ConvertProofOrdering(merkle.BuildSectorRangeProof(roots, sectorIndex, sectorIndex+1), sectorIndex)
	sp := types.StorageProof{
		ParentID: id,
		HashSet:  append(segmentProof, sectorProof...),
	}
	copy(sp.Segment[:], sector[segmentIndex*merkle.SegmentSize:])
	return sp, nil
}

// NewStorageManager returns an initialized storage manager.
func NewStorageManager(store SectorStore) *StorageManager {
	return &StorageManager{
		store: store,
	}
}
