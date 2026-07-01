//! freemkv-unlock — the unlock layer for the freemkv toolchain.
//!
//! An **unlocker removes a drive-level bus-encryption barrier** so the drive
//! serves readable (de-bus'd / de-scrambled) sectors. Content-key decryption is
//! a separate layer — the consumer's (libfreemkv's) job.
//!
//! This crate defines the [`Unlocker`] contract + the SCSI transport contract,
//! and holds the self-contained unlocker modules (firmware / AACS cert / CSS).
//! libfreemkv depends on this crate and dispatches via [`all_unlockers`]; it
//! never names an individual unlocker. To remove an unlocker, delete its module
//! dir and its one line in [`all_unlockers`] — nothing else changes.

pub mod scsi;

mod aacs;
mod css;
// `ld` is public ONLY for its drive-profile catalog (`ld::profiles` / the
// `Profiles` object) and, under the `emulation` feature, the unlock-handshake
// wire format the bdemu test-emulator needs. The unlocker impl itself
// (`LibreDrive`) is `pub(crate)` — clients still reach unlockers only through
// [`all_unlockers`]. `aacs` and `css` carry no such public catalog, so they
// stay fully private.
pub mod ld;

use scsi::ScsiTransport;

/// Drive identity an unlocker matches against — four raw INQUIRY-derived fields,
/// filled by the consumer (this crate parses no INQUIRY itself).
#[derive(Debug, Clone, Default)]
pub struct DriveId {
    pub vendor_id: String,
    pub product_revision: String,
    pub vendor_specific: String,
    pub firmware_date: String,
}

/// Bus-encryption class of the mounted disc, probed by the consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscKind {
    Unknown,
    Unencrypted,
    Aacs,
    Css,
}

/// A host certificate for the AACS cert handshake (raw; the consumer collects
/// these from its key sources and passes them in).
#[derive(Debug, Clone)]
pub struct HostCert {
    /// AACS 1.0 host private key (20 bytes).
    pub private_key: [u8; 20],
    /// AACS 1.0 host certificate (92 bytes).
    pub certificate: Vec<u8>,
    /// AACS 2.0 host private key (P-256, 32 bytes). `None` for AACS 1.0 only.
    pub private_key_v2: Option<[u8; 32]>,
    /// AACS 2.0 host certificate (type 0x11). `None` for AACS 1.0 only.
    pub certificate_v2: Option<Vec<u8>>,
}

/// Context handed to an unlocker: drive identity, disc kind, and (for the cert
/// route) the host certs the consumer collected.
pub struct UnlockCtx<'a> {
    pub drive_id: &'a DriveId,
    pub kind: DiscKind,
    pub host_certs: &'a [HostCert],
}

impl<'a> UnlockCtx<'a> {
    pub fn new(drive_id: &'a DriveId, kind: DiscKind, host_certs: &'a [HostCert]) -> Self {
        Self {
            drive_id,
            kind,
            host_certs,
        }
    }
}

/// What removing bus encryption yielded. `drive_unlocked` means the drive now
/// serves clear content (firmware route) — equivalent, for the gate, to a cert
/// `bus_key`.
#[derive(Debug, Clone, Default)]
pub struct Unlocked {
    pub vid: Option<[u8; 16]>,
    pub bus_key: Option<[u8; 16]>,
    pub drive_unlocked: bool,
}

/// Why an unlock produced no usable result. Only `Transport` is a hard error
/// (bus dead → consumer aborts); the rest mean "fall through to the next
/// unlocker".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockError {
    /// This unlocker does not apply (wrong disc kind / no profile / no certs).
    NotApplicable,
    /// The AACS cert route had no usable host certificate.
    NoUsableHostCert,
    /// The drive rejected the auth handshake.
    HandshakeRejected,
    /// Auth succeeded but no Volume ID could be read.
    VidUnavailable,
    /// A genuine SCSI transport fault (bus dead). The consumer aborts.
    Transport,
}

/// An unlocker removes a drive-level bus-encryption barrier. Implementors are
/// the self-contained modules in this crate; the consumer only ever sees the
/// trait, via [`all_unlockers`]. (Each module owns its own conversion from its
/// internal error to [`UnlockError`].)
///
/// NOTE: drive tuning (e.g. SET CD SPEED to lift riplock) is deliberately NOT
/// here — that is the consumer's concern, not bus removal.
pub trait Unlocker: Send + Sync {
    /// Short, stable identifier for this unlocker (e.g. "LibreDrive", "AACS",
    /// "CSS"). The ONE place a name lives — apps render the unlocker report from
    /// [`all_unlockers`], never hardcoding names, so adding/removing an unlocker
    /// updates every report with no app change.
    fn name(&self) -> &'static str;

    /// True if this unlocker applies to the given context (drive id + disc kind)
    /// during live dispatch — the gate [`crate::all_unlockers`] uses to decide
    /// whether to RUN it.
    fn matches(&self, ctx: &UnlockCtx) -> bool;

    /// Remove the bus-encryption barrier, returning what was learned.
    fn unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        ctx: &UnlockCtx,
    ) -> std::result::Result<Unlocked, UnlockError>;
}

/// Name of the unlocker that claims this drive by identity (for drive-info "is
/// this drive supported?" display), or `None`. A pure lookup — does NOT touch
/// the drive or unlock anything. Only the identity-keyed (drive-prep) unlocker
/// can answer from a `DriveId` alone; the disc-kind-keyed unlockers (AACS / CSS)
/// don't claim a drive sight-unseen, so they never match here.
pub fn unlocker_name(drive_id: &DriveId) -> Option<&'static str> {
    ld::firmware_name(drive_id)
}

/// Every unlocker, in dispatch order (firmware → cert → css). This is the ONLY
/// place an unlocker is named. Remove one = delete its line here + its module
/// dir; the consumer never changes.
pub fn all_unlockers() -> Vec<Box<dyn Unlocker>> {
    vec![
        Box::new(ld::LibreDrive::new()),
        Box::new(aacs::AacsCert::new()),
        Box::new(css::CssUnlocker::new()),
    ]
}
