package renterhost

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"reflect"
	"strings"
	"testing"

	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/encoding"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
	"golang.org/x/crypto/chacha20poly1305"
)

var randomTxn = func() types.Transaction {
	txn := types.Transaction{
		SiacoinInputs: []types.SiacoinInput{{
			UnlockConditions: types.UnlockConditions{
				Timelock:           types.BlockHeight(fastrand.Uint64n(10)),
				PublicKeys:         []types.SiaPublicKey{{Key: fastrand.Bytes(32)}},
				SignaturesRequired: fastrand.Uint64n(10),
			},
		}},
		SiacoinOutputs: []types.SiacoinOutput{{
			Value: types.SiacoinPrecision.Mul64(fastrand.Uint64n(100)),
		}},
		FileContracts: []types.FileContract{{
			FileSize:    fastrand.Uint64n(100),
			WindowStart: types.BlockHeight(fastrand.Uint64n(100)),
			WindowEnd:   types.BlockHeight(fastrand.Uint64n(100)),
			Payout:      types.SiacoinPrecision.Mul64(fastrand.Uint64n(100)),
			ValidProofOutputs: []types.SiacoinOutput{{
				Value: types.SiacoinPrecision.Mul64(fastrand.Uint64n(100)),
			}},
			MissedProofOutputs: []types.SiacoinOutput{{
				Value: types.SiacoinPrecision.Mul64(fastrand.Uint64n(100)),
			}},
			RevisionNumber: fastrand.Uint64n(100),
		}},
		FileContractRevisions: []types.FileContractRevision{{
			UnlockConditions: types.UnlockConditions{
				Timelock:           types.BlockHeight(fastrand.Uint64n(10)),
				PublicKeys:         []types.SiaPublicKey{{Key: fastrand.Bytes(32)}},
				SignaturesRequired: fastrand.Uint64n(10),
			},
			NewRevisionNumber: fastrand.Uint64n(100),
			NewFileSize:       fastrand.Uint64n(100),
			NewWindowStart:    types.BlockHeight(fastrand.Uint64n(100)),
			NewWindowEnd:      types.BlockHeight(fastrand.Uint64n(100)),
			NewValidProofOutputs: []types.SiacoinOutput{{
				Value: types.SiacoinPrecision.Mul64(fastrand.Uint64n(100)),
			}},
			NewMissedProofOutputs: []types.SiacoinOutput{{
				Value: types.SiacoinPrecision.Mul64(fastrand.Uint64n(100)),
			}},
		}},
		StorageProofs: []types.StorageProof{{
			HashSet: []crypto.Hash{{}},
		}},
		SiafundInputs: []types.SiafundInput{{
			UnlockConditions: types.UnlockConditions{
				Timelock:           types.BlockHeight(fastrand.Uint64n(10)),
				PublicKeys:         []types.SiaPublicKey{{Key: fastrand.Bytes(32)}},
				SignaturesRequired: fastrand.Uint64n(10),
			},
		}},
		SiafundOutputs: []types.SiafundOutput{{
			Value:      types.SiacoinPrecision.Mul64(fastrand.Uint64n(100)),
			ClaimStart: types.SiacoinPrecision.Mul64(fastrand.Uint64n(100)),
		}},
		MinerFees:     []types.Currency{types.SiacoinPrecision.Mul64(fastrand.Uint64n(100))},
		ArbitraryData: [][]byte{fastrand.Bytes(100)},
		TransactionSignatures: []types.TransactionSignature{{
			CoveredFields:  types.CoveredFields{MinerFees: []uint64{1, 2, 3}},
			PublicKeyIndex: fastrand.Uint64n(10),
			Timelock:       types.BlockHeight(fastrand.Uint64n(10)),
			Signature:      fastrand.Bytes(64),
		}},
	}
	fastrand.Read(txn.SiacoinInputs[0].ParentID[:])
	fastrand.Read(txn.SiacoinInputs[0].UnlockConditions.PublicKeys[0].Algorithm[:])
	fastrand.Read(txn.SiacoinOutputs[0].UnlockHash[:])
	fastrand.Read(txn.FileContracts[0].FileMerkleRoot[:])
	fastrand.Read(txn.FileContracts[0].UnlockHash[:])
	fastrand.Read(txn.FileContractRevisions[0].ParentID[:])
	fastrand.Read(txn.FileContractRevisions[0].NewFileMerkleRoot[:])
	fastrand.Read(txn.FileContractRevisions[0].NewUnlockHash[:])
	fastrand.Read(txn.StorageProofs[0].ParentID[:])
	fastrand.Read(txn.StorageProofs[0].Segment[:])
	fastrand.Read(txn.StorageProofs[0].HashSet[0][:])
	fastrand.Read(txn.SiafundInputs[0].ParentID[:])
	fastrand.Read(txn.SiafundOutputs[0].UnlockHash[:])
	fastrand.Read(txn.TransactionSignatures[0].ParentID[:])
	return txn
}()

func deepEqual(a, b interface{}) bool {
	return bytes.Equal(encoding.Marshal(a), encoding.Marshal(b))
}

type pipeRWC struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (p pipeRWC) Read(b []byte) (int, error) {
	return p.r.Read(b)
}
func (p pipeRWC) Write(b []byte) (int, error) {
	return p.w.Write(b)
}
func (p pipeRWC) Close() error {
	p.r.Close()
	return p.w.Close()
}

func newFakeConns() (io.ReadWriteCloser, io.ReadWriteCloser) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return pipeRWC{r1, w2}, pipeRWC{r2, w1}
}

type dummyKey struct{}

func (dummyKey) SignHash(hash crypto.Hash) []byte             { return make([]byte, 64) }
func (dummyKey) VerifyHash(hash crypto.Hash, sig []byte) bool { return true }

type arb struct {
	data interface{}
}

func (o arb) marshalledSize() int        { return len(encoding.Marshal(o.data)) }
func (o arb) marshalBuffer(b *objBuffer) { b.write(encoding.Marshal(o.data)) }
func (o arb) unmarshalBuffer(b *objBuffer) error {
	return encoding.Unmarshal(b.buf.Bytes(), o.data)
}

func TestSession(t *testing.T) {
	renter, host := newFakeConns()
	hostErr := make(chan error, 1)
	go func() {
		hostErr <- func() error {
			hs, err := NewHostSession(host, dummyKey{})
			if err != nil {
				return err
			}
			defer hs.Close()
			for {
				id, err := hs.ReadID()
				if err == ErrRenterClosed {
					return nil
				} else if err != nil {
					return err
				}
				switch id {
				case newSpecifier("Greet"):
					var name string
					if err := hs.ReadRequest(arb{&name}, 0); err != nil {
						return err
					}
					if name == "" {
						err = hs.WriteResponse(nil, errors.New("invalid name"))
					} else {
						err = hs.WriteResponse(arb{"Hello, " + name}, nil)
					}
					if err != nil {
						return err
					}
				default:
					return errors.New("unknown specifier")
				}
			}
		}()
	}()

	rs, err := NewRenterSession(renter, dummyKey{})
	if err != nil {
		t.Fatal(err)
	}
	var resp string
	if err := rs.WriteRequest(newSpecifier("Greet"), arb{"Foo"}); err != nil {
		t.Fatal(err)
	} else if err := rs.ReadResponse(arb{&resp}, 0); err != nil {
		t.Fatal(err)
	} else if resp != "Hello, Foo" {
		t.Fatal("unexpected response:", resp)
	}
	if err := rs.WriteRequest(newSpecifier("Greet"), arb{""}); err != nil {
		t.Fatal(err)
	} else if err := rs.ReadResponse(arb{&resp}, 0); !strings.Contains(err.Error(), "invalid name") {
		t.Fatal(err)
	}
	if err := rs.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-hostErr; err != nil {
		t.Fatal(err)
	}
}

func TestFormContract(t *testing.T) {
	renterReq := &RPCFormContractRequest{
		Transactions: []types.Transaction{randomTxn, randomTxn},
		RenterKey:    randomTxn.SiacoinInputs[0].UnlockConditions.PublicKeys[0],
	}
	hostAdditions := &RPCFormContractAdditions{
		Parents: []types.Transaction{randomTxn, randomTxn},
		Inputs:  randomTxn.SiacoinInputs,
		Outputs: randomTxn.SiacoinOutputs,
	}
	renterSigs := &RPCFormContractSignatures{
		ContractSignatures: randomTxn.TransactionSignatures,
		RevisionSignature:  randomTxn.TransactionSignatures[0],
	}
	hostSigs := &RPCFormContractSignatures{
		ContractSignatures: randomTxn.TransactionSignatures,
		RevisionSignature:  randomTxn.TransactionSignatures[0],
	}

	renter, host := newFakeConns()
	hostErr := make(chan error, 1)
	go func() {
		hostErr <- func() error {
			hs, err := NewHostSession(host, dummyKey{})
			if err != nil {
				return err
			}
			defer hs.Close()
			for {
				id, err := hs.ReadID()
				if err == ErrRenterClosed {
					return nil
				} else if err != nil {
					return err
				}
				switch id {
				case RPCFormContractID:
					var req RPCFormContractRequest
					if err := hs.ReadRequest(&req, 0); err != nil {
						return err
					} else if !deepEqual(&req, renterReq) {
						return errors.New("received request does not match sent request")
					}
					err = hs.WriteResponse(hostAdditions, nil)
					if err != nil {
						return err
					}
					var recvSigs RPCFormContractSignatures
					if err := hs.ReadResponse(&recvSigs, 0); err != nil {
						return err
					} else if !deepEqual(&recvSigs, renterSigs) {
						return errors.New("received sigs do not match sent sigs")
					}
					err = hs.WriteResponse(hostSigs, nil)
					if err != nil {
						return err
					}
				default:
					return errors.New("unknown specifier")
				}
			}
		}()
	}()

	rs, err := NewRenterSession(renter, dummyKey{})
	if err != nil {
		t.Fatal(err)
	}
	var recvAdditions RPCFormContractAdditions
	if err := rs.WriteRequest(RPCFormContractID, renterReq); err != nil {
		t.Fatal(err)
	} else if err := rs.ReadResponse(&recvAdditions, 0); err != nil {
		t.Fatal(err)
	} else if !deepEqual(&recvAdditions, hostAdditions) {
		t.Fatal("received additions do not match sent additions")
	}
	var recvSigs RPCFormContractSignatures
	if err := rs.WriteResponse(renterSigs, nil); err != nil {
		t.Fatal(err)
	} else if err := rs.ReadResponse(&recvSigs, 0); err != nil {
		t.Fatal(err)
	} else if !deepEqual(&recvSigs, hostSigs) {
		t.Fatal("received sigs do not match sent sigs")
	}
	if err := rs.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-hostErr; err != nil {
		t.Fatal(err)
	}
}

func TestChallenge(t *testing.T) {
	var s Session
	fastrand.Read(s.challenge[:])
	sig := s.SignChallenge(dummyKey{})
	if !s.VerifyChallenge(sig, dummyKey{}) {
		t.Fatal("challenge was not signed/verified correctly")
	}
}

func TestEncoding(t *testing.T) {
	objs := []ProtocolObject{
		(*objTransaction)(&randomTxn),
		(*objSiacoinOutput)(&randomTxn.SiacoinOutputs[0]),
		(*Specifier)(&randomTxn.SiacoinInputs[0].UnlockConditions.PublicKeys[0].Algorithm),
		(*objSiaPublicKey)(&randomTxn.SiacoinInputs[0].UnlockConditions.PublicKeys[0]),
		(*objSiacoinInput)(&randomTxn.SiacoinInputs[0]),
		(*objSiacoinOutput)(&randomTxn.SiacoinOutputs[0]),
		(*objFileContract)(&randomTxn.FileContracts[0]),
		(*objFileContractRevision)(&randomTxn.FileContractRevisions[0]),
		(*objStorageProof)(&randomTxn.StorageProofs[0]),
		(*objSiafundInput)(&randomTxn.SiafundInputs[0]),
		(*objSiafundOutput)(&randomTxn.SiafundOutputs[0]),
		(*objCoveredFields)(&randomTxn.TransactionSignatures[0].CoveredFields),
		(*objTransactionSignature)(&randomTxn.TransactionSignatures[0]),
		(*objTransaction)(&randomTxn),
		&RPCFormContractRequest{
			Transactions: []types.Transaction{randomTxn},
			RenterKey:    randomTxn.SiacoinInputs[0].UnlockConditions.PublicKeys[0],
		},
		&RPCFormContractAdditions{
			Parents: []types.Transaction{randomTxn},
			Inputs:  randomTxn.SiacoinInputs,
			Outputs: randomTxn.SiacoinOutputs,
		},
		&RPCFormContractSignatures{
			ContractSignatures: randomTxn.TransactionSignatures,
			RevisionSignature:  randomTxn.TransactionSignatures[0],
		},
		&RPCLockRequest{
			ContractID: randomTxn.FileContractRevisions[0].ParentID,
			Signature:  fastrand.Bytes(64),
			Timeout:    fastrand.Uint64n(100),
		},
		&RPCLockResponse{
			Revision:   randomTxn.FileContractRevisions[0],
			Signatures: randomTxn.TransactionSignatures,
		},
		&RPCReadRequest{
			Sections:             []RPCReadRequestSection{{}},
			NewRevisionNumber:    fastrand.Uint64n(100),
			NewValidProofValues:  randomTxn.MinerFees,
			NewMissedProofValues: randomTxn.MinerFees,
			Signature:            fastrand.Bytes(64),
		},
		&RPCReadResponse{
			Signature:   fastrand.Bytes(64),
			Data:        fastrand.Bytes(1024),
			MerkleProof: randomTxn.StorageProofs[0].HashSet,
		},
		&RPCSectorRootsRequest{
			RootOffset:           fastrand.Uint64n(100),
			NumRoots:             fastrand.Uint64n(100),
			NewRevisionNumber:    fastrand.Uint64n(100),
			NewValidProofValues:  randomTxn.MinerFees,
			NewMissedProofValues: randomTxn.MinerFees,
			Signature:            fastrand.Bytes(64),
		},
		&RPCSectorRootsResponse{
			SectorRoots: randomTxn.StorageProofs[0].HashSet,
			MerkleProof: randomTxn.StorageProofs[0].HashSet,
			Signature:   fastrand.Bytes(64),
		},
		&RPCSettingsResponse{
			Settings: fastrand.Bytes(100),
		},
		&RPCWriteRequest{
			Actions:              []RPCWriteAction{{Data: fastrand.Bytes(1024)}},
			NewRevisionNumber:    fastrand.Uint64n(100),
			NewValidProofValues:  randomTxn.MinerFees,
			NewMissedProofValues: randomTxn.MinerFees,
		},
		&RPCWriteMerkleProof{
			OldSubtreeHashes: randomTxn.StorageProofs[0].HashSet,
			OldLeafHashes:    randomTxn.StorageProofs[0].HashSet,
			NewMerkleRoot:    randomTxn.FileContractRevisions[0].NewFileMerkleRoot,
		},
		&RPCWriteResponse{
			Signature: fastrand.Bytes(64),
		},
	}
	for _, o := range objs {
		siaenc := encoding.Marshal(reflect.ValueOf(o).Elem().Interface())
		if exp := len(siaenc); o.marshalledSize() != exp {
			t.Errorf("marshalled size of %T is incorrect: got %v, expected %v", o, o.marshalledSize(), exp)
		}
		var b objBuffer
		o.marshalBuffer(&b)
		if exp := siaenc; !bytes.Equal(b.bytes(), exp) {
			t.Errorf("marshalled object (%T) is incorrect", o)
		}
		dup := reflect.New(reflect.TypeOf(o).Elem()).Interface()
		dup.(ProtocolObject).unmarshalBuffer(&b)
		if !deepEqual(dup, o) {
			t.Fatal("objects differ after unmarshalling")
		}
	}
}

func BenchmarkEncodeTransaction(b *testing.B) {
	b.Run("MarshalBuffer", func(b *testing.B) {
		b.SetBytes(int64((*objTransaction)(&randomTxn).marshalledSize()))
		var buf objBuffer
		for i := 0; i < b.N; i++ {
			buf.reset()
			(*objTransaction)(&randomTxn).marshalBuffer(&buf)
		}
	})
	b.Run("MarshalSia", func(b *testing.B) {
		b.SetBytes(int64(randomTxn.MarshalSiaSize()))
		var buf bytes.Buffer
		for i := 0; i < b.N; i++ {
			buf.Reset()
			randomTxn.MarshalSia(&buf)
		}
	})
}

func BenchmarkWriteMessage(b *testing.B) {
	aead, _ := chacha20poly1305.New(make([]byte, 32))
	s := &Session{
		conn: struct {
			io.Writer
			io.ReadCloser
		}{ioutil.Discard, nil},
		aead: aead,
	}
	obj := newSpecifier("Hello, World!")
	b.ReportAllocs()
	b.SetBytes(MinMessageSize)
	for i := 0; i < b.N; i++ {
		if err := s.writeMessage(&obj); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadMessage(b *testing.B) {
	b.Run("ID", func(b *testing.B) {
		obj := newSpecifier("Hello, World!")
		fastrand.Read(obj[:])

		var buf bytes.Buffer
		aead, _ := chacha20poly1305.New(make([]byte, 32))
		(&Session{
			conn: struct {
				io.Writer
				io.ReadCloser
			}{&buf, nil},
			aead: aead,
		}).writeMessage(&obj)

		var rwc struct {
			bytes.Reader
			io.WriteCloser
		}
		s := &Session{
			conn: &rwc,
			aead: aead,
		}

		b.ResetTimer()
		b.ReportAllocs()
		b.SetBytes(MinMessageSize)
		var obj2 Specifier
		for i := 0; i < b.N; i++ {
			rwc.Reset(buf.Bytes())
			if err := s.readMessage(&obj2, 0); err != nil {
				b.Fatal(err)
			} else if obj2 != obj {
				b.Fatal("mismatch")
			}
		}
	})
	b.Run("ReadResponse", func(b *testing.B) {
		resp := &RPCReadResponse{
			Signature:   fastrand.Bytes(64),
			Data:        fastrand.Bytes(SectorSize),
			MerkleProof: make([]crypto.Hash, 10),
		}

		var buf bytes.Buffer
		aead, _ := chacha20poly1305.New(make([]byte, 32))
		(&Session{
			conn: struct {
				io.Writer
				io.ReadCloser
			}{&buf, nil},
			aead: aead,
		}).writeMessage(resp)

		var rwc struct {
			bytes.Reader
			io.WriteCloser
		}
		s := &Session{
			conn: &rwc,
			aead: aead,
		}

		b.ResetTimer()
		b.ReportAllocs()
		b.SetBytes(int64(resp.marshalledSize()))
		var resp2 RPCReadResponse
		for i := 0; i < b.N; i++ {
			rwc.Reset(buf.Bytes())
			if err := s.readMessage(&resp2, SectorSize+MinMessageSize); err != nil {
				b.Fatal(err)
			}
		}
	})
}
