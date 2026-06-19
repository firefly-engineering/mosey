package walletsolana

// Write side of the mosey-session client: enough hand-rolled Solana
// transaction machinery to call the program's instructions over the same
// JSON-RPC caller the read path uses. We deliberately avoid a full Solana
// SDK — the program has four instructions and a fixed account layout, so
// the legacy message format, compact-u16 (shortvec) encoding, PDA
// derivation, and ed25519 signing fit in one file. Account contexts mirror
// programs/mosey-session/src/lib.rs.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"filippo.io/edwards25519"

	"github.com/firefly-engineering/mosey/wallet"
)

// systemProgramID is the SPL System Program ("111…11"), all-zero bytes.
var systemProgramID [32]byte

// pubkey is a 32-byte Solana account address.
type pubkey [32]byte

func toPubkey(k ed25519.PublicKey) pubkey {
	var p pubkey
	copy(p[:], k)
	return p
}

// accountMeta is one account reference in an instruction.
type accountMeta struct {
	key      pubkey
	isSigner bool
	writable bool
}

// instruction is a single program invocation.
type instruction struct {
	programID pubkey
	accounts  []accountMeta
	data      []byte
}

// ixDiscriminator is Anchor's 8-byte instruction tag: sha256("global:<snake>")[:8].
func ixDiscriminator(name string) [8]byte {
	sum := sha256.Sum256([]byte("global:" + name))
	var d [8]byte
	copy(d[:], sum[:8])
	return d
}

// onCurve reports whether the 32 bytes decode to a valid ed25519 point. A
// program-derived address must NOT be on the curve.
func onCurve(b [32]byte) bool {
	_, err := new(edwards25519.Point).SetBytes(b[:])
	return err == nil
}

// findPDA derives the canonical program-derived address for seeds: the
// highest bump (255 down) whose hash is off-curve. Mirrors Solana's
// Pubkey::find_program_address.
func findPDA(programID pubkey, seeds ...[]byte) (pubkey, uint8, error) {
	const pdaMarker = "ProgramDerivedAddress"
	for bump := 255; bump >= 0; bump-- {
		h := sha256.New()
		for _, s := range seeds {
			h.Write(s)
		}
		h.Write([]byte{byte(bump)})
		h.Write(programID[:])
		h.Write([]byte(pdaMarker))
		var cand pubkey
		copy(cand[:], h.Sum(nil))
		if !onCurve(cand) {
			return cand, uint8(bump), nil
		}
	}
	return pubkey{}, 0, errors.New("walletsolana: unable to find a valid PDA bump")
}

// appendShortVec writes a compact-u16 length prefix (7 bits/byte, MSB
// continuation), as Solana encodes array lengths.
func appendShortVec(dst []byte, n int) []byte {
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(dst, b)
		}
		dst = append(dst, b|0x80)
	}
}

// compiledMessage holds the ordered account keys and the serialized legacy
// message bytes (everything the signers sign over).
type compiledMessage struct {
	accountKeys []pubkey
	numSigners  int
	serialized  []byte
}

// compileMessage builds a legacy message from instructions. The fee payer
// is forced first; remaining accounts are ordered writable-signer,
// readonly-signer, writable-nonsigner, readonly-nonsigner, with flags
// merged across instructions (and the program ids appended read-only).
func compileMessage(feePayer pubkey, blockhash [32]byte, ixs []instruction) (compiledMessage, error) {
	type acc struct {
		key      pubkey
		isSigner bool
		writable bool
	}
	order := []pubkey{feePayer}
	merged := map[pubkey]*acc{feePayer: {key: feePayer, isSigner: true, writable: true}}
	add := func(key pubkey, signer, writable bool) {
		if a, ok := merged[key]; ok {
			a.isSigner = a.isSigner || signer
			a.writable = a.writable || writable
			return
		}
		merged[key] = &acc{key: key, isSigner: signer, writable: writable}
		order = append(order, key)
	}
	for _, ix := range ixs {
		for _, m := range ix.accounts {
			add(m.key, m.isSigner, m.writable)
		}
	}
	for _, ix := range ixs {
		add(ix.programID, false, false)
	}

	// Stable sort into the four ranks (order slice preserves first-seen,
	// which keeps the fee payer first within rank 0).
	var ws, rs, wn, rn []*acc
	for _, k := range order {
		a := merged[k]
		switch {
		case a.isSigner && a.writable:
			ws = append(ws, a)
		case a.isSigner:
			rs = append(rs, a)
		case a.writable:
			wn = append(wn, a)
		default:
			rn = append(rn, a)
		}
	}
	ranked := append(append(append(append([]*acc{}, ws...), rs...), wn...), rn...)

	keys := make([]pubkey, len(ranked))
	index := make(map[pubkey]int, len(ranked))
	for i, a := range ranked {
		keys[i] = a.key
		index[a.key] = i
	}
	numSigners := len(ws) + len(rs)
	header := [3]byte{byte(numSigners), byte(len(rs)), byte(len(rn))}

	var buf []byte
	buf = append(buf, header[0], header[1], header[2])
	buf = appendShortVec(buf, len(keys))
	for _, k := range keys {
		buf = append(buf, k[:]...)
	}
	buf = append(buf, blockhash[:]...)
	buf = appendShortVec(buf, len(ixs))
	for _, ix := range ixs {
		pi, ok := index[ix.programID]
		if !ok {
			return compiledMessage{}, fmt.Errorf("walletsolana: program id not in account list")
		}
		buf = append(buf, byte(pi))
		buf = appendShortVec(buf, len(ix.accounts))
		for _, m := range ix.accounts {
			buf = append(buf, byte(index[m.key]))
		}
		buf = appendShortVec(buf, len(ix.data))
		buf = append(buf, ix.data...)
	}
	return compiledMessage{accountKeys: keys, numSigners: numSigners, serialized: buf}, nil
}

// signTx signs a compiled message with the provided keys and returns the
// wire transaction (compact-u16 signatures || message). Each of the first
// numSigners account keys must have a corresponding private key in signers.
func signTx(msg compiledMessage, signers map[pubkey]ed25519.PrivateKey) ([]byte, error) {
	sigs := make([][]byte, msg.numSigners)
	for i := 0; i < msg.numSigners; i++ {
		key := msg.accountKeys[i]
		sk, ok := signers[key]
		if !ok {
			return nil, fmt.Errorf("walletsolana: missing signer for %s", wallet.EncodeBase58(key[:]))
		}
		sigs[i] = ed25519.Sign(sk, msg.serialized)
	}
	var tx []byte
	tx = appendShortVec(tx, len(sigs))
	for _, s := range sigs {
		tx = append(tx, s...)
	}
	tx = append(tx, msg.serialized...)
	return tx, nil
}

// getLatestBlockhash fetches a recent blockhash for tx construction.
func (s *Source) getLatestBlockhash(ctx context.Context) ([32]byte, error) {
	raw, err := s.call(ctx, "getLatestBlockhash", []any{
		map[string]any{"commitment": s.commitment},
	})
	if err != nil {
		return [32]byte{}, err
	}
	var out struct {
		Value struct {
			Blockhash string `json:"blockhash"`
		} `json:"value"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return [32]byte{}, fmt.Errorf("walletsolana: decode getLatestBlockhash: %w", err)
	}
	b, err := wallet.DecodeBase58(out.Value.Blockhash)
	if err != nil || len(b) != 32 {
		return [32]byte{}, fmt.Errorf("walletsolana: bad blockhash %q", out.Value.Blockhash)
	}
	var bh [32]byte
	copy(bh[:], b)
	return bh, nil
}

// sendTransaction submits a signed wire transaction and returns the
// signature (base58).
func (s *Source) sendTransaction(ctx context.Context, tx []byte) (string, error) {
	raw, err := s.call(ctx, "sendTransaction", []any{
		base64.StdEncoding.EncodeToString(tx),
		map[string]any{"encoding": "base64", "preflightCommitment": s.commitment},
	})
	if err != nil {
		return "", err
	}
	var sig string
	if err := json.Unmarshal(raw, &sig); err != nil {
		return "", fmt.Errorf("walletsolana: decode sendTransaction: %w", err)
	}
	return sig, nil
}

// sessionPDA / grantPDA derive the program accounts for a session key /
// (session, grantee), matching the program's seeds.
func (s *Source) programPubkey() (pubkey, error) {
	b, err := wallet.DecodeBase58(s.programID)
	if err != nil || len(b) != 32 {
		return pubkey{}, fmt.Errorf("walletsolana: bad program id %q", s.programID)
	}
	var p pubkey
	copy(p[:], b)
	return p, nil
}

func (s *Source) sessionPDA(sessionKey ed25519.PublicKey) (pubkey, uint8, error) {
	prog, err := s.programPubkey()
	if err != nil {
		return pubkey{}, 0, err
	}
	return findPDA(prog, []byte("session"), sessionKey)
}

func (s *Source) grantPDA(sessionAddr pubkey, grantee ed25519.PublicKey) (pubkey, uint8, error) {
	prog, err := s.programPubkey()
	if err != nil {
		return pubkey{}, 0, err
	}
	return findPDA(prog, []byte("grant"), sessionAddr[:], grantee)
}

// SessionAddress returns the base58 on-chain account (PDA) address for a
// session key — the value used as `--wallet-session` (attach) and
// `--session` (grant).
func (s *Source) SessionAddress(sessionKey ed25519.PublicKey) (string, error) {
	addr, _, err := s.sessionPDA(sessionKey)
	if err != nil {
		return "", err
	}
	return wallet.EncodeBase58(addr[:]), nil
}

// RegisterSession submits register_session, co-signed by the owner (payer)
// and the session key. Returns the transaction signature.
func (s *Source) RegisterSession(ctx context.Context, owner, sessionKey ed25519.PrivateKey) (string, error) {
	prog, err := s.programPubkey()
	if err != nil {
		return "", err
	}
	ownerPub := toPubkey(owner.Public().(ed25519.PublicKey))
	sessPub := toPubkey(sessionKey.Public().(ed25519.PublicKey))
	sessionAddr, _, err := s.sessionPDA(sessionKey.Public().(ed25519.PublicKey))
	if err != nil {
		return "", err
	}
	disc := ixDiscriminator("register_session")
	ix := instruction{
		programID: prog,
		accounts: []accountMeta{
			{key: sessionAddr, isSigner: false, writable: true},
			{key: sessPub, isSigner: true, writable: false},
			{key: ownerPub, isSigner: true, writable: true},
			{key: systemProgramID, isSigner: false, writable: false},
		},
		data: disc[:],
	}
	return s.submit(ctx, ownerPub, []instruction{ix}, map[pubkey]ed25519.PrivateKey{
		ownerPub: owner,
		sessPub:  sessionKey,
	})
}

// Grant submits grant(grantee, caps, expiry), owner-signed. sessionKey
// identifies the session whose grant table is updated.
func (s *Source) Grant(ctx context.Context, owner ed25519.PrivateKey, sessionKey, grantee ed25519.PublicKey, caps wallet8, expiry int64) (string, error) {
	ownerPub := toPubkey(owner.Public().(ed25519.PublicKey))
	ix, err := s.grantIx(ownerPub, sessionKey, grantee, uint8(caps), expiry)
	if err != nil {
		return "", err
	}
	return s.submit(ctx, ownerPub, []instruction{ix}, map[pubkey]ed25519.PrivateKey{ownerPub: owner})
}

// TransferOwnership submits transfer_ownership(new_owner), owner-signed.
// sessionKey identifies the session whose owner field is updated.
func (s *Source) TransferOwnership(ctx context.Context, owner ed25519.PrivateKey, sessionKey, newOwner ed25519.PublicKey) (string, error) {
	ownerPub := toPubkey(owner.Public().(ed25519.PublicKey))
	ix, err := s.transferOwnershipIx(ownerPub, sessionKey, newOwner)
	if err != nil {
		return "", err
	}
	return s.submit(ctx, ownerPub, []instruction{ix}, map[pubkey]ed25519.PrivateKey{ownerPub: owner})
}

// BumpEpoch submits bump_epoch — a one-transaction mass-revoke that
// invalidates every grant stamped with the prior epoch. Owner-signed.
func (s *Source) BumpEpoch(ctx context.Context, owner ed25519.PrivateKey, sessionKey ed25519.PublicKey) (string, error) {
	ownerPub := toPubkey(owner.Public().(ed25519.PublicKey))
	ix, err := s.bumpEpochIx(ownerPub, sessionKey)
	if err != nil {
		return "", err
	}
	return s.submit(ctx, ownerPub, []instruction{ix}, map[pubkey]ed25519.PrivateKey{ownerPub: owner})
}

// submit compiles, signs, sends, and confirms one transaction. It blocks
// until the signature reaches the configured commitment so a follow-up
// command (e.g. register → grant) sees the on-chain effect.
func (s *Source) submit(ctx context.Context, feePayer pubkey, ixs []instruction, signers map[pubkey]ed25519.PrivateKey) (string, error) {
	bh, err := s.getLatestBlockhash(ctx)
	if err != nil {
		return "", err
	}
	msg, err := compileMessage(feePayer, bh, withPriority(ixs))
	if err != nil {
		return "", err
	}
	tx, err := signTx(msg, signers)
	if err != nil {
		return "", err
	}
	sig, err := s.sendTransaction(ctx, tx)
	if err != nil {
		return "", err
	}
	if err := s.confirmTransaction(ctx, sig, tx); err != nil {
		return sig, err
	}
	return sig, nil
}

// confirmTransaction polls getSignatureStatuses until sig reaches a
// confirmed/finalized commitment (or fails). It also rebroadcasts the
// signed tx periodically: a single send can be dropped on a busy cluster
// and Solana does not re-include a tx automatically, so resending the
// same bytes lands it while its blockhash is still valid. Pass tx == nil
// to disable rebroadcast.
func (s *Source) confirmTransaction(ctx context.Context, sig string, tx []byte) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	ticks := 0
	for {
		raw, err := s.call(ctx, "getSignatureStatuses", []any{
			[]string{sig},
			map[string]any{"searchTransactionHistory": true},
		})
		if err == nil {
			var out struct {
				Value []*struct {
					ConfirmationStatus string          `json:"confirmationStatus"`
					Err                json.RawMessage `json:"err"`
				} `json:"value"`
			}
			if jerr := json.Unmarshal(raw, &out); jerr == nil && len(out.Value) > 0 && out.Value[0] != nil {
				st := out.Value[0]
				if len(st.Err) > 0 && string(st.Err) != "null" {
					return fmt.Errorf("walletsolana: transaction %s failed: %s", sig, st.Err)
				}
				if st.ConfirmationStatus == "confirmed" || st.ConfirmationStatus == "finalized" {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			// The transaction was already submitted (we have its
			// signature); we just stopped waiting for confirmation.
			return fmt.Errorf("walletsolana: transaction %s submitted but not confirmed in time — it may still land; check it on an explorer: %w", sig, ctx.Err())
		case <-ticker.C:
			ticks++
			if tx != nil && ticks%3 == 0 {
				_, _ = s.sendTransaction(ctx, tx) // rebroadcast; ignore transient errors
			}
		}
	}
}

// wallet8 is the on-chain caps byte (mirrors wallet.Caps' underlying u8).
type wallet8 = uint8
