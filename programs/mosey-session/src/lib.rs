//! mosey-session — the on-chain root of trust for wallet auth.
//!
//! Records session ownership and owner-issued grants, and emits events
//! the mosey server's snapshot cache follows. It never sees connection
//! keys, transport keys, or session bytes — only wallets. Minting is
//! owner-only (deep delegation lives off-chain); see
//! docs/src/wallet-auth.md#on-chain-program-anchor.

use anchor_lang::prelude::*;

// Placeholder program id — replace with the deployed id (and the
// canonical default baked into mosey) before mainnet.
declare_id!("11111111111111111111111111111111");

/// Capability bits, mirroring wallet.Caps. No "owner" bit: ownership is
/// the structural Session.owner field.
const CAP_WRITE: u8 = 1;
const CAP_RESIZE: u8 = 2;
const CAP_FORGE: u8 = 4;
const ALL_CAPS: u8 = CAP_WRITE | CAP_RESIZE | CAP_FORGE;

#[program]
pub mod mosey_session {
    use super::*;

    /// Register a session. Co-signed by the session keypair, proving the
    /// registrant controls that terminal identity (anti-squat).
    pub fn register_session(ctx: Context<RegisterSession>) -> Result<()> {
        let s = &mut ctx.accounts.session;
        s.session_key = ctx.accounts.session_key.key();
        s.owner = ctx.accounts.owner.key();
        s.epoch = 0;
        s.bump = ctx.bumps.session;
        emit!(SessionRegistered {
            session: s.key(),
            session_key: s.session_key,
            owner: s.owner,
        });
        Ok(())
    }

    /// Transfer ownership to a new wallet.
    pub fn transfer_ownership(ctx: Context<OwnerOnly>, new_owner: Pubkey) -> Result<()> {
        let s = &mut ctx.accounts.session;
        let previous = s.owner;
        s.owner = new_owner;
        emit!(OwnershipTransferred {
            session: s.key(),
            previous,
            new_owner,
        });
        Ok(())
    }

    /// Mint (or update) a grant. Owner-only; caps must be a subset of the
    /// known bits. The grant is stamped with the current epoch.
    pub fn grant(ctx: Context<CreateGrant>, grantee: Pubkey, caps: u8, expiry: i64) -> Result<()> {
        require!(caps & !ALL_CAPS == 0, MoseyError::InvalidCaps);
        let s = &ctx.accounts.session;
        let g = &mut ctx.accounts.grant;
        g.session = s.key();
        g.grantee = grantee;
        g.caps = caps;
        g.expiry = expiry;
        g.epoch = s.epoch;
        g.bump = ctx.bumps.grant;
        emit!(GrantMinted {
            session: s.key(),
            grantee,
            caps,
            expiry,
            epoch: s.epoch,
        });
        Ok(())
    }

    /// Revoke a grant by closing its account (rent refunded to the owner).
    pub fn revoke(ctx: Context<Revoke>) -> Result<()> {
        emit!(GrantRevoked {
            session: ctx.accounts.session.key(),
            grantee: ctx.accounts.grant.grantee,
        });
        Ok(())
    }

    /// Bump the session epoch — a one-transaction mass-revoke. Grants
    /// stamped with an older epoch are dead until re-granted.
    pub fn bump_epoch(ctx: Context<OwnerOnly>) -> Result<()> {
        let s = &mut ctx.accounts.session;
        s.epoch = s.epoch.checked_add(1).ok_or(MoseyError::EpochOverflow)?;
        emit!(EpochBumped {
            session: s.key(),
            epoch: s.epoch,
        });
        Ok(())
    }
}

#[account]
pub struct Session {
    pub session_key: Pubkey,
    pub owner: Pubkey,
    pub epoch: u16,
    pub bump: u8,
}

impl Session {
    pub const SIZE: usize = 32 + 32 + 2 + 1;
}

#[account]
pub struct Grant {
    pub session: Pubkey,
    pub grantee: Pubkey,
    pub caps: u8,
    pub expiry: i64,
    pub epoch: u16,
    pub bump: u8,
}

impl Grant {
    pub const SIZE: usize = 32 + 32 + 1 + 8 + 2 + 1;
}

#[derive(Accounts)]
pub struct RegisterSession<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + Session::SIZE,
        seeds = [b"session", session_key.key().as_ref()],
        bump,
    )]
    pub session: Account<'info, Session>,
    /// The persisted session keypair co-signs, proving control of the
    /// session identity.
    pub session_key: Signer<'info>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct OwnerOnly<'info> {
    #[account(
        mut,
        has_one = owner,
        seeds = [b"session", session.session_key.as_ref()],
        bump = session.bump,
    )]
    pub session: Account<'info, Session>,
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(grantee: Pubkey)]
pub struct CreateGrant<'info> {
    #[account(
        has_one = owner,
        seeds = [b"session", session.session_key.as_ref()],
        bump = session.bump,
    )]
    pub session: Account<'info, Session>,
    #[account(
        init_if_needed,
        payer = owner,
        space = 8 + Grant::SIZE,
        seeds = [b"grant", session.key().as_ref(), grantee.as_ref()],
        bump,
    )]
    pub grant: Account<'info, Grant>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Revoke<'info> {
    #[account(
        has_one = owner,
        seeds = [b"session", session.session_key.as_ref()],
        bump = session.bump,
    )]
    pub session: Account<'info, Session>,
    #[account(
        mut,
        close = owner,
        seeds = [b"grant", session.key().as_ref(), grant.grantee.as_ref()],
        bump = grant.bump,
    )]
    pub grant: Account<'info, Grant>,
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[error_code]
pub enum MoseyError {
    #[msg("caps contain unknown bits")]
    InvalidCaps,
    #[msg("epoch overflow")]
    EpochOverflow,
}

#[event]
pub struct SessionRegistered {
    pub session: Pubkey,
    pub session_key: Pubkey,
    pub owner: Pubkey,
}

#[event]
pub struct OwnershipTransferred {
    pub session: Pubkey,
    pub previous: Pubkey,
    pub new_owner: Pubkey,
}

#[event]
pub struct GrantMinted {
    pub session: Pubkey,
    pub grantee: Pubkey,
    pub caps: u8,
    pub expiry: i64,
    pub epoch: u16,
}

#[event]
pub struct GrantRevoked {
    pub session: Pubkey,
    pub grantee: Pubkey,
}

#[event]
pub struct EpochBumped {
    pub session: Pubkey,
    pub epoch: u16,
}
