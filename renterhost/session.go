// Package renterhost implements the handshake and transport for the Sia
// renter-host protocol.
package renterhost // import "lukechampine.com/us/renterhost"

import (
	"bytes"
	"crypto/cipher"
	"io"

	"github.com/pkg/errors"
	"gitlab.com/NebulousLabs/Sia/crypto"
	"gitlab.com/NebulousLabs/Sia/types"
	"gitlab.com/NebulousLabs/fastrand"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

// MinMessageSize is the minimum size of an RPC message. If an encoded message
// would be smaller than MinMessageSize, the sender MAY pad it with random data.
// This hinders traffic analysis by obscuring the true sizes of messages.
const MinMessageSize = 4096

// A HashSigner signs hashes with a secret key.
type HashSigner interface {
	SignHash(hash crypto.Hash) []byte
}

// A HashVerifier verifies that a hash was signed with a secret key.
type HashVerifier interface {
	VerifyHash(hash crypto.Hash, sig []byte) bool
}

// An RPCError may be sent instead of a response object to any RPC.
type RPCError struct {
	Type        Specifier
	Data        []byte // structure depends on Type
	Description string // human-readable error string
}

// Error implements the error interface.
func (e *RPCError) Error() string {
	return e.Description
}

// helper type for encoding and decoding RPC response messages, which can
// represent either valid data or an error.
type rpcResponse struct {
	err  *RPCError
	data ProtocolObject
}

// A Session is an ongoing exchange of RPCs via the renter-host protocol.
type Session struct {
	conn      io.ReadWriteCloser
	aead      cipher.AEAD
	inbuf     objBuffer
	outbuf    objBuffer
	challenge [16]byte
	isRenter  bool
}

// SetChallenge sets the current session challenge.
func (s *Session) SetChallenge(challenge [16]byte) {
	s.challenge = challenge
}

func hashChallenge(challenge [16]byte) [32]byte {
	c := make([]byte, 32)
	copy(c[:16], "challenge")
	copy(c[16:], challenge[:])
	return blake2b.Sum256(c)
}

// SignChallenge signs the current session challenge.
func (s *Session) SignChallenge(hs HashSigner) []byte {
	return hs.SignHash(hashChallenge(s.challenge))
}

// VerifyChallenge verifies a signature of the current session challenge.
func (s *Session) VerifyChallenge(sig []byte, hv HashVerifier) bool {
	return hv.VerifyHash(hashChallenge(s.challenge), sig)
}

func (s *Session) writeMessage(obj ProtocolObject) error {
	// generate random nonce
	nonce := make([]byte, 256)[:s.aead.NonceSize()] // avoid heap alloc
	fastrand.Read(nonce)

	// pad short messages to MinMessageSize
	msgSize := 8 + s.aead.NonceSize() + obj.marshalledSize() + s.aead.Overhead()
	if msgSize < MinMessageSize {
		msgSize = MinMessageSize
	}

	// write length prefix, nonce, and object directly into buffer
	s.outbuf.reset()
	s.outbuf.grow(msgSize)
	s.outbuf.writePrefix(msgSize - 8)
	s.outbuf.write(nonce)
	obj.marshalBuffer(&s.outbuf)

	// encrypt the object in-place
	msg := s.outbuf.bytes()[:msgSize]
	msgNonce := msg[8:][:len(nonce)]
	payload := msg[8+len(nonce) : msgSize-s.aead.Overhead()]
	s.aead.Seal(payload[:0], msgNonce, payload, nil)

	_, err := s.conn.Write(msg)
	return err
}

func (s *Session) readMessage(obj ProtocolObject, maxLen uint64) error {
	if maxLen < MinMessageSize {
		maxLen = MinMessageSize
	}
	s.inbuf.reset()
	s.inbuf.copyN(s.conn, 8)
	if s.inbuf.Err() != nil {
		return s.inbuf.Err()
	}
	msgSize := s.inbuf.readUint64()
	if msgSize > maxLen {
		return errors.Errorf("message size (%v bytes) exceeds maxLen of %v bytes", msgSize, maxLen)
	} else if msgSize < uint64(s.aead.NonceSize()+s.aead.Overhead()) {
		return errors.Errorf("message size (%v bytes) is too small (nonce + MAC is %v bytes)", msgSize, s.aead.NonceSize()+s.aead.Overhead())
	}

	s.inbuf.reset()
	s.inbuf.grow(int(msgSize))
	if err := s.inbuf.copyN(s.conn, msgSize); err != nil {
		return err
	}

	nonce := s.inbuf.next(s.aead.NonceSize())
	paddedPayload := s.inbuf.bytes()
	_, err := s.aead.Open(paddedPayload[:0], nonce, paddedPayload, nil)
	if err != nil {
		return err
	}
	return obj.unmarshalBuffer(&s.inbuf)
}

// WriteRequest sends an encrypted RPC request, comprising an RPC ID and a
// request object.
func (s *Session) WriteRequest(rpcID Specifier, req ProtocolObject) (err error) {
	err = s.writeMessage(&rpcID)
	if err == nil && req != nil {
		err = s.writeMessage(req)
	}
	return
}

// ReadID reads an RPC request ID. If the renter sends the session termination
// signal, ReadID returns ErrRenterClosed.
func (s *Session) ReadID() (rpcID Specifier, err error) {
	err = s.readMessage(&rpcID, MinMessageSize)
	if rpcID == loopExit {
		err = ErrRenterClosed
	}
	return
}

// ReadRequest reads an RPC request using the new loop protocol.
func (s *Session) ReadRequest(req ProtocolObject, maxLen uint64) error {
	return s.readMessage(req, maxLen)
}

// WriteResponse writes an RPC response object or error. Either resp or err must
// be nil. If err is an *RPCError, it is sent directly; otherwise, a generic
// RPCError is created from err's Error string.
func (s *Session) WriteResponse(resp ProtocolObject, err error) error {
	re, ok := err.(*RPCError)
	if err != nil && !ok {
		re = &RPCError{Description: err.Error()}
	}
	return s.writeMessage(&rpcResponse{re, resp})
}

// ReadResponse reads an RPC response. If the response is an error, it is
// returned directly.
func (s *Session) ReadResponse(resp ProtocolObject, maxLen uint64) error {
	rr := rpcResponse{nil, resp}
	if err := s.readMessage(&rr, maxLen); err != nil {
		return err
	} else if rr.err != nil {
		return rr.err
	}
	return nil
}

// Close gracefully terminates the RPC loop and closes the connection.
func (s *Session) Close() error {
	if s.isRenter {
		s.WriteRequest(loopExit, nil)
	}
	return s.conn.Close()
}

func hashKeys(k1, k2 [32]byte) crypto.Hash {
	return blake2b.Sum256(append(append(make([]byte, 0, len(k1)+len(k2)), k1[:]...), k2[:]...))
}

// NewHostSession conducts the hosts's half of the renter-host protocol
// handshake, returning a Session that can be used to handle RPC requests.
func NewHostSession(conn io.ReadWriteCloser, hs HashSigner) (*Session, error) {
	var req loopKeyExchangeRequest
	if err := req.readFrom(conn); err != nil {
		return nil, err
	}

	var supportsChaCha bool
	for _, c := range req.Ciphers {
		if c == cipherChaCha20Poly1305 {
			supportsChaCha = true
		}
	}
	if !supportsChaCha {
		(&loopKeyExchangeResponse{Cipher: cipherNoOverlap}).writeTo(conn)
		return nil, errors.New("no supported ciphers")
	}

	xsk, xpk := crypto.GenerateX25519KeyPair()
	resp := loopKeyExchangeResponse{
		Cipher:    cipherChaCha20Poly1305,
		PublicKey: xpk,
		Signature: hs.SignHash(hashKeys(req.PublicKey, xpk)),
	}
	if err := resp.writeTo(conn); err != nil {
		return nil, err
	}

	cipherKey := crypto.DeriveSharedSecret(xsk, req.PublicKey)
	aead, _ := chacha20poly1305.New(cipherKey[:]) // no error possible
	s := &Session{
		conn:     conn,
		aead:     aead,
		isRenter: false,
	}
	fastrand.Read(s.challenge[:])
	// hack: cast challenge to Specifier to make it a ProtocolObject
	if err := s.writeMessage((*Specifier)(&s.challenge)); err != nil {
		return nil, err
	}
	return s, nil
}

// NewRenterSession conducts the renter's half of the renter-host protocol
// handshake, returning a Session that can be used to make RPC requests.
//
// Note that hostdb.HostPublicKey implements the HashVerifier interface.
func NewRenterSession(conn io.ReadWriteCloser, hv HashVerifier) (*Session, error) {
	xsk, xpk := crypto.GenerateX25519KeyPair()
	req := &loopKeyExchangeRequest{
		PublicKey: xpk,
		Ciphers:   []Specifier{cipherChaCha20Poly1305},
	}
	if err := req.writeTo(conn); err != nil {
		return nil, err
	}
	var resp loopKeyExchangeResponse
	if err := resp.readFrom(conn); err != nil {
		return nil, err
	}
	// validate the signature before doing anything else
	if !hv.VerifyHash(hashKeys(req.PublicKey, resp.PublicKey), resp.Signature) {
		return nil, errors.New("host's handshake signature was invalid")
	}
	if resp.Cipher == cipherNoOverlap {
		return nil, errors.New("host does not support any of our proposed ciphers")
	} else if resp.Cipher != cipherChaCha20Poly1305 {
		return nil, errors.New("host selected unsupported cipher")
	}

	cipherKey := crypto.DeriveSharedSecret(xsk, resp.PublicKey)
	aead, _ := chacha20poly1305.New(cipherKey[:]) // no error possible
	s := &Session{
		conn:     conn,
		aead:     aead,
		isRenter: true,
	}
	// hack: cast challenge to Specifier to make it a ProtocolObject
	if err := s.readMessage((*Specifier)(&s.challenge), MinMessageSize); err != nil {
		return nil, err
	}
	return s, nil
}

// Handshake objects
type (
	loopKeyExchangeRequest struct {
		PublicKey crypto.X25519PublicKey
		Ciphers   []Specifier
	}

	loopKeyExchangeResponse struct {
		PublicKey crypto.X25519PublicKey
		Signature []byte
		Cipher    Specifier
	}
)

// A Specifier is a generic identification tag.
type Specifier [16]byte

func (s Specifier) String() string {
	return string(bytes.Trim(s[:], string(0)))
}

func newSpecifier(str string) Specifier {
	if len(str) > 16 {
		panic("specifier is too long")
	}
	var s Specifier
	copy(s[:], str)
	return s
}

// Handshake specifiers
var (
	loopEnter = newSpecifier("LoopEnter")
	loopExit  = newSpecifier("LoopExit")
)

// ErrRenterClosed is returned by (*Session).ReadID when the renter sends the
// session termination signal.
var ErrRenterClosed = errors.New("renter has terminated session")

// RPC ciphers
var (
	cipherChaCha20Poly1305 = newSpecifier("ChaCha20Poly1305")
	cipherNoOverlap        = newSpecifier("NoOverlap")
)

// RPC IDs
var (
	RPCFormContractID  = newSpecifier("LoopFormContract")
	RPCLockID          = newSpecifier("LoopLock")
	RPCReadID          = newSpecifier("LoopRead")
	RPCRenewContractID = newSpecifier("LoopRenew")
	RPCSectorRootsID   = newSpecifier("LoopSectorRoots")
	RPCSettingsID      = newSpecifier("LoopSettings")
	RPCUnlockID        = newSpecifier("LoopUnlock")
	RPCWriteID         = newSpecifier("LoopWrite")
)

// Read/Write actions
var (
	RPCWriteActionAppend = newSpecifier("Append")
	RPCWriteActionTrim   = newSpecifier("Trim")
	RPCWriteActionSwap   = newSpecifier("Swap")
	RPCWriteActionUpdate = newSpecifier("Update")

	RPCReadStop = newSpecifier("ReadStop")
)

// RPC request/response objects
type (
	// RPCFormContractRequest contains the request parameters for the
	// FormContract RPC.
	RPCFormContractRequest struct {
		Transactions []types.Transaction
		RenterKey    types.SiaPublicKey
	}

	// RPCFormContractAdditions contains the parent transaction, inputs, and
	// outputs added by the host when negotiating a file contract.
	RPCFormContractAdditions struct {
		Parents []types.Transaction
		Inputs  []types.SiacoinInput
		Outputs []types.SiacoinOutput
	}

	// RPCFormContractSignatures contains the signatures for a contract
	// transaction and initial revision. These signatures are sent by both the
	// renter and host during contract formation and renewal.
	RPCFormContractSignatures struct {
		ContractSignatures []types.TransactionSignature
		RevisionSignature  types.TransactionSignature
	}

	// RPCLockRequest contains the request parameters for the Lock RPC.
	RPCLockRequest struct {
		ContractID types.FileContractID
		Signature  []byte
		Timeout    uint64
	}

	// RPCLockResponse contains the response data for the Lock RPC.
	RPCLockResponse struct {
		Acquired     bool
		NewChallenge [16]byte
		Revision     types.FileContractRevision
		Signatures   []types.TransactionSignature
	}

	// RPCReadRequestSection is a section requested in RPCReadRequest.
	RPCReadRequestSection struct {
		MerkleRoot crypto.Hash
		Offset     uint32
		Length     uint32
	}

	// RPCReadRequest contains the request parameters for the Read RPC.
	RPCReadRequest struct {
		Sections    []RPCReadRequestSection
		MerkleProof bool

		NewRevisionNumber    uint64
		NewValidProofValues  []types.Currency
		NewMissedProofValues []types.Currency
		Signature            []byte
	}

	// RPCReadResponse contains the response data for the Read RPC.
	RPCReadResponse struct {
		Signature   []byte
		Data        []byte
		MerkleProof []crypto.Hash
	}

	// RPCSectorRootsRequest contains the request parameters for the SectorRoots RPC.
	RPCSectorRootsRequest struct {
		RootOffset uint64
		NumRoots   uint64

		NewRevisionNumber    uint64
		NewValidProofValues  []types.Currency
		NewMissedProofValues []types.Currency
		Signature            []byte
	}

	// RPCSectorRootsResponse contains the response data for the SectorRoots RPC.
	RPCSectorRootsResponse struct {
		Signature   []byte
		SectorRoots []crypto.Hash
		MerkleProof []crypto.Hash
	}

	// RPCSettingsResponse contains the response data for the SettingsResponse RPC.
	RPCSettingsResponse struct {
		Settings []byte // JSON-encoded hostdb.HostSettings
	}

	// RPCWriteRequest contains the request parameters for the Write RPC.
	RPCWriteRequest struct {
		Actions     []RPCWriteAction
		MerkleProof bool

		NewRevisionNumber    uint64
		NewValidProofValues  []types.Currency
		NewMissedProofValues []types.Currency
	}

	// RPCWriteAction is a generic Write action. The meaning of each field
	// depends on the Type of the action.
	RPCWriteAction struct {
		Type Specifier
		A, B uint64
		Data []byte
	}

	// RPCWriteMerkleProof contains the optional Merkle proof for response data
	// for the Write RPC.
	RPCWriteMerkleProof struct {
		OldSubtreeHashes []crypto.Hash
		OldLeafHashes    []crypto.Hash
		NewMerkleRoot    crypto.Hash
	}

	// RPCWriteResponse contains the response data for the Write RPC.
	RPCWriteResponse struct {
		Signature []byte
	}
)
