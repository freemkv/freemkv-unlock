//! freemkv-unlock — the unlock layer for the freemkv toolchain.
//!
//! An **unlocker removes a drive-level bus-encryption barrier** so the drive
//! serves readable (de-bus'd / de-scrambled) sectors. Content-key decryption
//! is a separate layer — the consumer's (libfreemkv's) job.
//!
//! This crate defines the [`Unlocker`] contract + the SCSI transport
//! contract, and holds the self-contained unlocker modules (firmware / AACS
//! cert / CSS). The consumer (libfreemkv) assembles its own dispatch list from
//! the exported unlocker types and drives them all through the same trait.

pub mod scsi;

mod aacs;
mod css;
// Shared best-effort AACS Volume ID read, used by every route that opens the
// drive to raw reads (freemkv / MT1959 / Renesas). See `vid`.
mod vid;
// `ld` is public only for its drive-profile catalog + (under `emulation`) the
// handshake wire format bdemu needs; the unlocker impl stays `pub(crate)`.
// See docs/module-visibility.md — module visibility rationale.
pub mod ld;
// `renesas` is public for its `is_renesas` drive-probe (dead bus vs. "not a
// Renesas drive"); the unlocker impl stays `pub(crate)`.
// See docs/module-visibility.md — module visibility rationale.
pub mod renesas;
// `freemkv` self-identifies rather than matching a bundled profile, so it
// stays fully private. See docs/module-visibility.md — module visibility rationale.
mod freemkv;

use scsi::ScsiTransport;

// The five unlockers, exposed as concrete types so the consumer assembles its
// own dispatch list and injects each one's deps at construction (certs → AACS)
// — no central factory to thread another unlocker's config through.
pub use aacs::AacsUnlocker;
pub use css::DvdUnlocker;
pub use freemkv::FreemkvUnlocker;
pub use ld::LdUnlocker;
pub use renesas::Renesas;

/// Drive identity an unlocker matches against — four raw INQUIRY-derived fields,
/// filled by the consumer (this crate parses no INQUIRY itself).
#[derive(Debug, Clone, Default)]
pub struct DriveId {
    pub vendor_id: String,
    pub product_id: String,
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

/// Per-attempt context the consumer hands to EVERY unlocker, uniformly: the
/// drive identity and the mounted disc's kind. These are the shared facts the
/// dispatch loop knows; anything an individual unlocker needs beyond them (the
/// AACS cert route's host certs) is injected into THAT unlocker at construction,
/// so the loop and the other unlockers never see it. See docs/module-visibility.md.
pub struct UnlockCtx<'a> {
    pub drive_id: &'a DriveId,
    pub kind: DiscKind,
}

impl<'a> UnlockCtx<'a> {
    pub fn new(drive_id: &'a DriveId, kind: DiscKind) -> Self {
        Self { drive_id, kind }
    }
}

/// What a successful unlock captured: the Volume ID (best-effort — may be `None`
/// even on success) and, for the cert route, the bus key the read path applies
/// to de-bus content. Returned inside the `Some` of [`Unlocker::unlock`]; there
/// is no `drive_unlocked` flag — "unlocked" is simply `unlock()` returning
/// `Some`, uniformly for every route.
#[derive(Clone, Default)]
pub struct Unlocked {
    pub vid: Option<[u8; 16]>,
    pub bus_key: Option<[u8; 16]>,
}

// Hand-written, REDACTING Debug: `bus_key`/`vid` are key material that must
// never reach a log in plaintext; presence (Some/None) stays observable.
// See docs/unlocked-debug-redaction.md — full rationale.
impl std::fmt::Debug for Unlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unlocked")
            .field("vid", &self.vid.map(|_| "[redacted]"))
            .field("bus_key", &self.bus_key.map(|_| "[redacted]"))
            .finish()
    }
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
/// the self-contained modules in this crate; the consumer drives them all
/// through this trait. (Each module owns its own conversion from its internal
/// error to [`UnlockError`].)
///
/// NOTE: drive tuning (e.g. SET CD SPEED to lift riplock) is deliberately NOT
/// here — that is the consumer's concern, not bus removal.
pub trait Unlocker: Send + Sync {
    /// Short, stable identifier for this unlocker (e.g. "freemkv", "LD",
    /// "AACS", "DVD", "Renesas"). The ONE place a name lives — apps render the
    /// unlocker report from `name()`, never hardcoding names, so adding/removing
    /// an unlocker updates every report with no app change.
    fn name(&self) -> &'static str;

    /// Attempt to unlock the drive, whatever the mechanism (vendor CDB, profile
    /// firmware handshake, AACS cert AKE, CSS auth):
    /// `Ok(Some(unlocked))` = this one unlocked it (read `vid`/`bus_key`, stop);
    /// `Ok(None)` = not this unlocker's drive (try the next); `Err(Transport)` =
    /// dead bus (abort). Only a dead bus is `Err` — a missing VID, rejected
    /// handshake, missing cert, or wrong disc kind all fall through as `Ok(None)`
    /// (the VID inside `Unlocked` is best-effort). `&self`: stateless, returns
    /// what it learned rather than stashing it.
    fn unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        ctx: &UnlockCtx,
    ) -> std::result::Result<Option<Unlocked>, UnlockError>;
}

/// The shared "only a dead bus is fatal" rule every unlocker uses to turn its
/// mechanism's `Result<Unlocked>` into the trait's outcome: success → `Some`, a
/// dead bus → `Err(Transport)`, any other failure → `None` (fall through to the
/// next unlocker). Written once here so the five unlockers stay identical in
/// error handling and differ only in their CDBs and checks.
pub(crate) fn fallthrough(
    r: std::result::Result<Unlocked, UnlockError>,
) -> std::result::Result<Option<Unlocked>, UnlockError> {
    match r {
        Ok(u) => Ok(Some(u)),
        Err(UnlockError::Transport) => Err(UnlockError::Transport),
        Err(_) => Ok(None),
    }
}

/// Name of the unlocker that claims this drive by identity (for drive-info "is
/// this drive supported?" display), or `None`. A pure lookup — does NOT touch
/// the drive or unlock anything. Only the identity-keyed (drive-prep) unlocker
/// can answer from a `DriveId` alone; the disc-kind-keyed unlockers (AACS / CSS)
/// don't claim a drive sight-unseen, so they never match here.
pub fn unlocker_name(drive_id: &DriveId) -> Option<&'static str> {
    ld::firmware_name(drive_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical dispatch order the consumer assembles (freemkv → firmware →
    // Renesas → cert → css). It lives in the consumer now (no factory), but the
    // types are ours, so pin their names here so a rename is caught crate-local.
    fn canonical_unlockers() -> Vec<Box<dyn Unlocker>> {
        vec![
            Box::new(FreemkvUnlocker::new()),
            Box::new(LdUnlocker::new()),
            Box::new(Renesas::new()),
            Box::new(AacsUnlocker::new(Vec::new())),
            Box::new(DvdUnlocker::new()),
        ]
    }

    #[test]
    fn unlocker_names_are_stable() {
        let names: Vec<&'static str> = canonical_unlockers().iter().map(|u| u.name()).collect();
        assert_eq!(names, vec!["freemkv", "LD", "Renesas", "AACS", "DVD"]);
    }

    /// The uniform contract every unlocker obeys, whatever its mechanism: on a
    /// DEAD BUS, `unlock()` either declined before touching it (`Ok(false)`) or
    /// engaged it and reported the fault (`Err(Transport)`) — but NEVER claims a
    /// dead bus as unlocked, and NEVER surfaces a non-`Transport` hard error.
    /// This is the guardrail that was missing: it holds the next new unlocker to
    /// the same discipline the loop relies on.
    #[test]
    fn no_unlocker_claims_a_dead_bus_or_hard_errors() {
        let id = DriveId::default();
        let ctx = UnlockCtx::new(&id, DiscKind::Aacs);
        for u in canonical_unlockers() {
            let name = u.name();
            let mut t = scsi::mock::MockTransport::always(scsi::mock::Reply::TransportFault);
            match u.unlock(&mut t, &ctx) {
                Ok(None) => {}                    // declined before touching — fine
                Err(UnlockError::Transport) => {} // engaged, dead bus — fine
                other => panic!("{name} violated the dead-bus contract: {other:?}"),
            }
        }
    }

    /// `unlocker_name` is a PURE lookup — it must answer from the `DriveId`
    /// alone, and only the identity-keyed unlocker can claim a drive this way.
    #[test]
    fn unlocker_name_is_a_pure_identity_lookup() {
        assert_eq!(unlocker_name(&DriveId::default()), None);
    }

    // `bus_key`/`vid` are key material; `Debug` must NOT print those bytes.
    // MUTATION: restoring `#[derive(Debug)]` prints the raw byte arrays, so
    // the marker bytes appear in the output and this test goes red.
    #[test]
    fn unlocked_debug_redacts_key_material() {
        let u = Unlocked {
            vid: Some([0xAB; 16]),
            bus_key: Some([0xCD; 16]),
        };
        let s = format!("{u:?}");
        // A derived Debug renders `[171, 171, ...]` (0xAB) / `[205, ...]` (0xCD).
        assert!(!s.contains("171"), "vid bytes must not appear: {s}");
        assert!(!s.contains("205"), "bus_key bytes must not appear: {s}");
        assert!(s.contains("[redacted]"), "must mark redaction: {s}");
        // Presence (Some/None) stays observable.
        assert!(s.contains("Some"), "must still show a key WAS present: {s}");
    }
}
