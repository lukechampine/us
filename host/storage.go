package host

import (
	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"lukechampine.com/us/merkle"
	"lukechampine.com/us/renterhost"
)

func readSection(sec renterhost.RPCReadRequestSection, proof bool, ss SectorStore) (*renterhost.RPCReadResponse, error) {
	sector, err := ss.Sector(sec.MerkleRoot)
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

func readSectors(id types.FileContractID, offset, length uint64, ss SectorStore) (*renterhost.RPCSectorRootsResponse, error) {
	roots, err := ss.ContractRoots(id)
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

func considerModifications(id types.FileContractID, actions []renterhost.RPCWriteAction, proof bool, ss SectorStore) (*renterhost.RPCWriteMerkleProof, func() error, error) {
	sectorRoots, err := ss.ContractRoots(id)
	if err != nil {
		return nil, nil, err
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
			sector, err := ss.Sector(newRoots[sectorIndex])
			if err != nil {
				return nil, nil, err
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

	apply := func() error {
		if err := ss.SetContractRoots(id, newRoots); err != nil {
			return err
		}
		for _, root := range sectorsRemoved {
			if err := ss.DeleteSector(root); err != nil {
				return err
			}
			delete(gainedSectorData, root)
		}
		for root, sector := range gainedSectorData {
			if err := ss.AddSector(root, sector); err != nil {
				return err
			}
		}
		return nil
	}

	return merkleResp, apply, nil
}

func moveContractRoots(from, to types.FileContractID, ss SectorStore) error {
	roots, err := ss.ContractRoots(from)
	if err != nil {
		return err
	} else if err := ss.SetContractRoots(to, roots); err != nil {
		return err
	} else if err := ss.SetContractRoots(from, nil); err != nil {
		return err
	}
	return nil
}

func buildStorageProof(id types.FileContractID, index uint64, ss SectorStore) (types.StorageProof, error) {
	sectorIndex := int(index / merkle.SegmentsPerSector)
	segmentIndex := int(index % merkle.SegmentsPerSector)

	roots, err := ss.ContractRoots(id)
	if err != nil {
		return types.StorageProof{}, err
	}
	root := roots[sectorIndex]
	sector, err := ss.Sector(root)
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
