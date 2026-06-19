package walletsolana

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
)

// This file factors the owner-signed instructions into pubkey-only
// builders shared by two paths: the local-key sign+submit methods in
// tx.go (used by `mosey session …`), and the unsigned-transaction
// builders below (used by `mosey web`, where the owner's signature comes
// from a browser wallet, not a local key — so the gateway never holds
// owner authority). See docs/src/web-attach.md (governance).

func (s *Source) transferOwnershipIx(ownerPub pubkey, sessionKey, newOwner ed25519.PublicKey) (instruction, error) {
	prog, err := s.programPubkey()
	if err != nil {
		return instruction{}, err
	}
	sessionAddr, _, err := s.sessionPDA(sessionKey)
	if err != nil {
		return instruction{}, err
	}
	disc := ixDiscriminator("transfer_ownership")
	data := append(append([]byte(nil), disc[:]...), newOwner...)
	return instruction{
		programID: prog,
		accounts: []accountMeta{
			{key: sessionAddr, isSigner: false, writable: true},
			{key: ownerPub, isSigner: true, writable: true},
		},
		data: data,
	}, nil
}

func (s *Source) grantIx(ownerPub pubkey, sessionKey, grantee ed25519.PublicKey, caps uint8, expiry int64) (instruction, error) {
	prog, err := s.programPubkey()
	if err != nil {
		return instruction{}, err
	}
	sessionAddr, _, err := s.sessionPDA(sessionKey)
	if err != nil {
		return instruction{}, err
	}
	grantAddr, _, err := s.grantPDA(sessionAddr, grantee)
	if err != nil {
		return instruction{}, err
	}
	disc := ixDiscriminator("grant")
	data := append([]byte(nil), disc[:]...)
	data = append(data, grantee...)
	data = append(data, caps)
	data = binary.LittleEndian.AppendUint64(data, uint64(expiry))
	return instruction{
		programID: prog,
		accounts: []accountMeta{
			{key: sessionAddr, isSigner: false, writable: false},
			{key: grantAddr, isSigner: false, writable: true},
			{key: ownerPub, isSigner: true, writable: true},
			{key: systemProgramID, isSigner: false, writable: false},
		},
		data: data,
	}, nil
}

func (s *Source) bumpEpochIx(ownerPub pubkey, sessionKey ed25519.PublicKey) (instruction, error) {
	prog, err := s.programPubkey()
	if err != nil {
		return instruction{}, err
	}
	sessionAddr, _, err := s.sessionPDA(sessionKey)
	if err != nil {
		return instruction{}, err
	}
	disc := ixDiscriminator("bump_epoch")
	return instruction{
		programID: prog,
		accounts: []accountMeta{
			{key: sessionAddr, isSigner: false, writable: true},
			{key: ownerPub, isSigner: true, writable: true},
		},
		data: append([]byte(nil), disc[:]...),
	}, nil
}

func (s *Source) revokeIx(ownerPub pubkey, sessionKey, grantee ed25519.PublicKey) (instruction, error) {
	prog, err := s.programPubkey()
	if err != nil {
		return instruction{}, err
	}
	sessionAddr, _, err := s.sessionPDA(sessionKey)
	if err != nil {
		return instruction{}, err
	}
	grantAddr, _, err := s.grantPDA(sessionAddr, grantee)
	if err != nil {
		return instruction{}, err
	}
	disc := ixDiscriminator("revoke")
	return instruction{
		programID: prog,
		accounts: []accountMeta{
			{key: sessionAddr, isSigner: false, writable: false},
			{key: grantAddr, isSigner: false, writable: true},
			{key: ownerPub, isSigner: true, writable: true},
		},
		data: append([]byte(nil), disc[:]...),
	}, nil
}

// compileUnsignedTx serializes msg as an unsigned legacy transaction: a
// compact-u16 signature count, that many 64-byte zero placeholders, then
// the message. This is the wire form a browser wallet deserializes,
// signs (filling the fee-payer slot), and re-serializes for submission.
func compileUnsignedTx(msg compiledMessage) []byte {
	var tx []byte
	tx = appendShortVec(tx, msg.numSigners)
	tx = append(tx, make([]byte, msg.numSigners*64)...)
	tx = append(tx, msg.serialized...)
	return tx
}

// buildUnsigned fetches a blockhash, compiles the message with feePayer
// first, and returns the unsigned transaction bytes for external signing.
func (s *Source) buildUnsigned(ctx context.Context, feePayer pubkey, ixs []instruction) ([]byte, error) {
	bh, err := s.getLatestBlockhash(ctx)
	if err != nil {
		return nil, err
	}
	msg, err := compileMessage(feePayer, bh, ixs)
	if err != nil {
		return nil, err
	}
	return compileUnsignedTx(msg), nil
}

// BuildTransferOwnership returns the unsigned transfer_ownership
// transaction for the owner wallet to sign in a browser. ownerPub is the
// fee payer + sole signer.
func (s *Source) BuildTransferOwnership(ctx context.Context, ownerPub ed25519.PublicKey, sessionKey, newOwner ed25519.PublicKey) ([]byte, error) {
	op := toPubkey(ownerPub)
	ix, err := s.transferOwnershipIx(op, sessionKey, newOwner)
	if err != nil {
		return nil, err
	}
	return s.buildUnsigned(ctx, op, []instruction{ix})
}

// BuildGrant returns the unsigned on-chain grant transaction.
func (s *Source) BuildGrant(ctx context.Context, ownerPub ed25519.PublicKey, sessionKey, grantee ed25519.PublicKey, caps uint8, expiry int64) ([]byte, error) {
	op := toPubkey(ownerPub)
	ix, err := s.grantIx(op, sessionKey, grantee, caps, expiry)
	if err != nil {
		return nil, err
	}
	return s.buildUnsigned(ctx, op, []instruction{ix})
}

// BuildBumpEpoch returns the unsigned bump_epoch (mass-revoke) transaction.
func (s *Source) BuildBumpEpoch(ctx context.Context, ownerPub ed25519.PublicKey, sessionKey ed25519.PublicKey) ([]byte, error) {
	op := toPubkey(ownerPub)
	ix, err := s.bumpEpochIx(op, sessionKey)
	if err != nil {
		return nil, err
	}
	return s.buildUnsigned(ctx, op, []instruction{ix})
}

// BuildRevoke returns the unsigned revoke transaction that closes the
// grant for grantee (rent refunds to the owner).
func (s *Source) BuildRevoke(ctx context.Context, ownerPub ed25519.PublicKey, sessionKey, grantee ed25519.PublicKey) ([]byte, error) {
	op := toPubkey(ownerPub)
	ix, err := s.revokeIx(op, sessionKey, grantee)
	if err != nil {
		return nil, err
	}
	return s.buildUnsigned(ctx, op, []instruction{ix})
}

// SubmitSigned sends a fully-signed wire transaction (from a browser
// wallet) and blocks until it confirms. Returns the signature.
func (s *Source) SubmitSigned(ctx context.Context, tx []byte) (string, error) {
	sig, err := s.sendTransaction(ctx, tx)
	if err != nil {
		return "", err
	}
	if err := s.confirmTransaction(ctx, sig, tx); err != nil {
		return sig, err
	}
	return sig, nil
}
