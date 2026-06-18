//! Behavioral tests for the mosey-session program, run in-process with
//! litesvm (no validator, no network). Mirrors the on-chain account model
//! in ../mosey-session/src/lib.rs. Instructions are hand-built with the
//! granular solana crates (Anchor discriminator + manual arg layout) so
//! this harness pulls no anchor types.
//!
//! Covers what the devnet round-trip can't cheaply do: epoch bump, revoke,
//! and the rejection paths (invalid caps, non-owner) that would burn SOL.

use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::path::PathBuf;
use std::str::FromStr;

// Must match declare_id! in the program (and the .so it was built with).
const PROGRAM_ID: &str = "D64mDEWvdThvEXMaxpeLRAP94wst2WcMiyzb3VqZ23T7";

// Cap bits, mirroring the program.
const CAP_WRITE: u8 = 1;
const CAP_RESIZE: u8 = 2;

fn program_id() -> Address {
    Address::from_str(PROGRAM_ID).unwrap()
}

fn system_program() -> Address {
    solana_system_interface::program::ID
}

fn so_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../mosey-session/target/deploy/mosey_session.so");
    p
}

/// Anchor's 8-byte instruction tag: sha256("global:<name>")[..8].
fn disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    let mut d = [0u8; 8];
    d.copy_from_slice(&h[..8]);
    d
}

fn session_pda(session_key: &Address) -> Address {
    Address::find_program_address(&[b"session", session_key.as_ref()], &program_id()).0
}

fn grant_pda(session_acct: &Address, grantee: &Address) -> Address {
    Address::find_program_address(&[b"grant", session_acct.as_ref(), grantee.as_ref()], &program_id()).0
}

/// Boots an SVM with the program loaded, a funded owner, and a registered
/// session owned by that wallet. Returns separate bindings so callers can
/// borrow the svm mutably while reading the keypairs.
fn registered() -> (LiteSVM, Keypair, Keypair, Address) {
    let mut svm = LiteSVM::new();
    svm.add_program_from_file(program_id(), so_path())
        .expect("load program .so");
    let owner = Keypair::new();
    svm.airdrop(&owner.pubkey(), 100_000_000_000).unwrap();
    let session = Keypair::new();
    let session_acct = session_pda(&session.pubkey());

    let ix = Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(session_acct, false),
            AccountMeta::new_readonly(session.pubkey(), true),
            AccountMeta::new(owner.pubkey(), true),
            AccountMeta::new_readonly(system_program(), false),
        ],
        data: disc("register_session").to_vec(),
    };
    send(&mut svm, ix, &owner, &[&session]).expect("register_session");
    (svm, owner, session, session_acct)
}

fn grant_ix(session_acct: &Address, signer: &Address, grantee: &Address, caps: u8, expiry: i64) -> Instruction {
    let mut data = disc("grant").to_vec();
    data.extend_from_slice(grantee.as_ref());
    data.push(caps);
    data.extend_from_slice(&expiry.to_le_bytes());
    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new_readonly(*session_acct, false),
            AccountMeta::new(grant_pda(session_acct, grantee), false),
            AccountMeta::new(*signer, true),
            AccountMeta::new_readonly(system_program(), false),
        ],
        data,
    }
}

fn send(svm: &mut LiteSVM, ix: Instruction, payer: &Keypair, extra: &[&Keypair]) -> Result<(), String> {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let bh = svm.latest_blockhash();
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &signers, bh);
    svm.send_transaction(tx).map(|_| ()).map_err(|e| format!("{:?}", e.err))
}

// Session account: disc(8) | session_key(32) | owner(32) | epoch(u16) | bump(1)
fn session_owner(svm: &LiteSVM, session_acct: &Address) -> Address {
    let data = svm.get_account(session_acct).unwrap().data;
    Address::from(<[u8; 32]>::try_from(&data[40..72]).unwrap())
}
fn session_epoch(svm: &LiteSVM, session_acct: &Address) -> u16 {
    let data = svm.get_account(session_acct).unwrap().data;
    u16::from_le_bytes([data[72], data[73]])
}
// Grant account: disc(8) | session(32) | grantee(32) | caps(1) | expiry(8) | epoch(u16)
fn grant_caps_epoch(svm: &LiteSVM, session_acct: &Address, grantee: &Address) -> Option<(u8, u16)> {
    let acct = svm.get_account(&grant_pda(session_acct, grantee))?;
    if acct.data.len() < 75 {
        return None;
    }
    Some((acct.data[72], u16::from_le_bytes([acct.data[73], acct.data[74]])))
}

#[test]
fn register_sets_owner_and_zero_epoch() {
    let (svm, owner, _session, sa) = registered();
    assert_eq!(session_owner(&svm, &sa), owner.pubkey());
    assert_eq!(session_epoch(&svm, &sa), 0);
}

#[test]
fn grant_records_caps() {
    let (mut svm, owner, _session, sa) = registered();
    let grantee = Keypair::new().pubkey();
    send(&mut svm, grant_ix(&sa, &owner.pubkey(), &grantee, CAP_WRITE | CAP_RESIZE, 0), &owner, &[])
        .expect("grant");
    assert_eq!(grant_caps_epoch(&svm, &sa, &grantee), Some((CAP_WRITE | CAP_RESIZE, 0)));
}

#[test]
fn invalid_caps_rejected() {
    let (mut svm, owner, _session, sa) = registered();
    let grantee = Keypair::new().pubkey();
    // 0x8 is outside ALL_CAPS (write|resize|forge = 0x7) → MoseyError::InvalidCaps.
    let err = send(&mut svm, grant_ix(&sa, &owner.pubkey(), &grantee, 0x8, 0), &owner, &[]);
    assert!(err.is_err(), "grant with unknown caps bit must fail");
}

#[test]
fn non_owner_cannot_grant() {
    let (mut svm, _owner, _session, sa) = registered();
    let attacker = Keypair::new();
    svm.airdrop(&attacker.pubkey(), 10_000_000_000).unwrap();
    let grantee = Keypair::new().pubkey();
    // Signed + paid by attacker, but the session's has_one = owner check fails.
    let err = send(&mut svm, grant_ix(&sa, &attacker.pubkey(), &grantee, CAP_WRITE, 0), &attacker, &[]);
    assert!(err.is_err(), "a non-owner must not be able to grant");
}

#[test]
fn bump_epoch_increments() {
    let (mut svm, owner, _session, sa) = registered();
    let ix = Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(sa, false),
            AccountMeta::new(owner.pubkey(), true),
        ],
        data: disc("bump_epoch").to_vec(),
    };
    send(&mut svm, ix, &owner, &[]).expect("bump_epoch");
    assert_eq!(session_epoch(&svm, &sa), 1);
}

#[test]
fn revoke_closes_grant() {
    let (mut svm, owner, _session, sa) = registered();
    let grantee = Keypair::new().pubkey();
    send(&mut svm, grant_ix(&sa, &owner.pubkey(), &grantee, CAP_WRITE, 0), &owner, &[]).expect("grant");
    assert!(grant_caps_epoch(&svm, &sa, &grantee).is_some());

    let ix = Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new_readonly(sa, false),
            AccountMeta::new(grant_pda(&sa, &grantee), false),
            AccountMeta::new(owner.pubkey(), true),
        ],
        data: disc("revoke").to_vec(),
    };
    send(&mut svm, ix, &owner, &[]).expect("revoke");
    assert!(
        svm.get_account(&grant_pda(&sa, &grantee)).map_or(true, |a| a.data.is_empty()),
        "revoked grant account should be closed",
    );
}

#[test]
fn transfer_changes_owner_and_old_owner_loses_authority() {
    let (mut svm, owner, _session, sa) = registered();
    let new_owner = Keypair::new().pubkey();
    let mut data = disc("transfer_ownership").to_vec();
    data.extend_from_slice(new_owner.as_ref());
    let ix = Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(sa, false),
            AccountMeta::new(owner.pubkey(), true),
        ],
        data,
    };
    send(&mut svm, ix, &owner, &[]).expect("transfer_ownership");
    assert_eq!(session_owner(&svm, &sa), new_owner);

    // The old owner can no longer grant.
    let grantee = Keypair::new().pubkey();
    let err = send(&mut svm, grant_ix(&sa, &owner.pubkey(), &grantee, CAP_WRITE, 0), &owner, &[]);
    assert!(err.is_err(), "old owner must lose authority after transfer");
}
