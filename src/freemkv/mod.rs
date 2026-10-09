//! Common unlock sequence for freemkv's flashed and runtime protocol implementations.
//! Backend capabilities select optional settings; encryption activation is required.
//! Hardware backends provide installation, verification and VID retrieval.

pub mod renesas;

use crate::firmware::{
    Feature, FirmwareIdentity, MEMREAD_LEN, MIN_ALLOC_LEN, REGION_FREE, SPEED_MAX, STATE_OFF,
    STATE_ON, build_identity_cdb, build_memread_cdb, build_set_cdb,
};
use crate::scsi::{DataDirection, ScsiTransport, is_dead_bus};
use crate::{UnlockCtx, UnlockError, Unlocked, Unlocker};

/// Allocation the IDENTITY / DUMPALL data-in phase reads back (a fixed 64-byte
/// window, matching [`MEMREAD_LEN`]).
const RESP_LEN: usize = MEMREAD_LEN;

type BackendResult<T> = std::result::Result<T, UnlockError>;

trait Backend {
    fn command_timeout_ms(&self, _feature: Feature) -> u32 {
        5_000
    }
    fn prepare(&mut self, _scsi: &mut dyn ScsiTransport, _installed: bool) -> BackendResult<()> {
        Ok(())
    }
    fn validate_set_reply(
        &self,
        _reply: &crate::scsi::ScsiResult,
        _data: &[u8],
    ) -> BackendResult<()> {
        Ok(())
    }
    fn install(&mut self, _scsi: &mut dyn ScsiTransport, installed: bool) -> BackendResult<()> {
        if installed {
            Ok(())
        } else {
            Err(UnlockError::NotApplicable)
        }
    }
    fn capabilities(&self) -> crate::protocol::Capabilities;
    fn verify(&self, _scsi: &mut dyn ScsiTransport) -> BackendResult<()> {
        Ok(())
    }
    fn get_vid(&self, scsi: &mut dyn ScsiTransport) -> BackendResult<Option<[u8; 16]>> {
        crate::vid::read_aacs_vid(scsi)
    }
    fn finish(&mut self, _scsi: &mut dyn ScsiTransport, _success: bool) -> BackendResult<()> {
        Ok(())
    }
}
struct Preinstalled {
    capabilities: crate::protocol::Capabilities,
}
impl Backend for Preinstalled {
    fn capabilities(&self) -> crate::protocol::Capabilities {
        self.capabilities
    }
}

#[derive(Default)]
pub struct FreemkvUnlocker;

impl FreemkvUnlocker {
    pub fn new() -> Self {
        FreemkvUnlocker
    }

    fn probe(
        &self,
        scsi: &mut dyn ScsiTransport,
    ) -> BackendResult<Option<crate::protocol::ProtocolIdentity>> {
        let mut buf = [0; RESP_LEN];
        match scsi.execute(
            &build_identity_cdb(RESP_LEN as u16),
            DataDirection::FromDevice,
            &mut buf,
            5_000,
        ) {
            Ok(r) if r.status == 0 && r.bytes_transferred <= buf.len() => {
                let bytes = &buf[..r.bytes_transferred];
                match crate::protocol::ProtocolIdentity::parse(bytes) {
                    Some(id) => Ok(Some(id)),
                    None if FirmwareIdentity::parse(bytes).is_some() => {
                        Err(UnlockError::NotApplicable)
                    }
                    None => Ok(None),
                }
            }
            Ok(_) => Ok(None),
            Err(e) if is_dead_bus(&e) => Err(UnlockError::Transport),
            Err(_) => Ok(None),
        }
    }
    #[cfg(test)]
    fn identify(&self, scsi: &mut dyn ScsiTransport) -> BackendResult<bool> {
        match self.probe(scsi) {
            Ok(id) => Ok(id.is_some()),
            Err(UnlockError::NotApplicable) => Ok(false),
            Err(e) => Err(e),
        }
    }

    // Issue a `Set(feature, state)` over the required data-in phase. Ok(()) on GOOD status;
    // NotApplicable if rejected; Transport only on a dead bus.
    #[cfg(test)]
    fn set(&self, scsi: &mut dyn ScsiTransport, feature: Feature, state: u8) -> BackendResult<()> {
        self.set_checked(scsi, feature, state, None)
    }
    fn set_checked(
        &self,
        scsi: &mut dyn ScsiTransport,
        feature: Feature,
        state: u8,
        backend: Option<&dyn Backend>,
    ) -> std::result::Result<(), UnlockError> {
        let cdb = build_set_cdb(feature, state);
        // SET needs the data-in phase its CDB advertises — a no-data SET is aborted
        // (CHECK CONDITION, HW-confirmed on BU40N fw 0.8.1). Buffer sized from the SAME
        // const the CDB advertises (MIN_ALLOC_LEN) so the transfer length has one source.
        let mut buf = [0u8; MIN_ALLOC_LEN as usize];
        match scsi.execute(
            &cdb,
            DataDirection::FromDevice,
            &mut buf,
            backend.map_or(5_000, |b| b.command_timeout_ms(feature)),
        ) {
            Ok(r) if r.status == 0 => match backend {
                Some(b) => b.validate_set_reply(&r, &buf),
                None => Ok(()),
            },
            Ok(r) => {
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "freemkv_set_rejected",
                    feature = ?feature,
                    state,
                    status = r.status,
                    "freemkv SET rejected by the drive"
                );
                Err(UnlockError::NotApplicable)
            }
            Err(e) => {
                if is_dead_bus(&e) {
                    tracing::warn!(
                        target: "freemkv::disc",
                        phase = "freemkv_set_transport_fault",
                        feature = ?feature,
                        "transport fault on a freemkv SET; aborting"
                    );
                    return Err(UnlockError::Transport);
                }
                tracing::debug!(
                    target: "freemkv::disc",
                    phase = "freemkv_set_rejected_as_err",
                    feature = ?feature,
                    status = e.status,
                    "freemkv SET rejected (via Err)"
                );
                Err(UnlockError::NotApplicable)
            }
        }
    }

    /// DumpAll diagnostic RAM read (DUMPALL): return the 64-byte window at
    /// `addr`. A host-side diagnostic path only — not used by the unlock flow.
    #[allow(dead_code)]
    fn dump_ram(
        &self,
        scsi: &mut dyn ScsiTransport,
        addr: u32,
    ) -> std::result::Result<[u8; MEMREAD_LEN], UnlockError> {
        let cdb = build_memread_cdb(addr);
        let mut buf = [0u8; MEMREAD_LEN];
        match scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000) {
            Ok(r) if r.status == 0 && r.bytes_transferred >= MEMREAD_LEN => Ok(buf),
            Ok(_) => Err(UnlockError::NotApplicable),
            Err(e) => {
                if is_dead_bus(&e) {
                    Err(UnlockError::Transport)
                } else {
                    Err(UnlockError::NotApplicable)
                }
            }
        }
    }

    fn full_unlock(&self, scsi: &mut dyn ScsiTransport) -> BackendResult<Unlocked> {
        use crate::protocol::Implementation;
        let identity = self.probe(scsi)?;
        let installed = identity.is_some();
        let mut backend: Box<dyn Backend> = match identity {
            Some(id) if id.capabilities.implementation() == Implementation::Firmware => {
                Box::new(Preinstalled {
                    capabilities: id.capabilities,
                })
            }
            Some(_) => Box::new(renesas::Backend::new()),
            None if renesas::is_renesas(scsi)? => Box::new(renesas::Backend::new()),
            None => return Err(UnlockError::NotApplicable),
        };
        backend.prepare(scsi, installed)?;
        let result = {
            let mut critical =
                crate::scsi::CriticalGuard::enter(scsi).map_err(|_| UnlockError::Transport)?;
            let scsi = &mut *critical;
            let result = (|| {
                backend.install(scsi, installed)?;
                if !installed {
                    let id = self.probe(scsi)?.ok_or(UnlockError::NotApplicable)?;
                    if id.capabilities != backend.capabilities() {
                        return Err(UnlockError::NotApplicable);
                    }
                }
                self.activate(scsi, &*backend)?;
                backend.verify(scsi)?;
                let vid = backend.get_vid(scsi)?;
                Ok(Unlocked { vid, bus_key: None })
            })();
            backend.finish(scsi, result.is_ok())?;
            result
        };
        scsi.pause(std::time::Duration::ZERO)
            .map_err(|_| UnlockError::Transport)?;
        result
    }

    fn activate(&self, scsi: &mut dyn ScsiTransport, backend: &dyn Backend) -> BackendResult<()> {
        let capabilities = backend.capabilities();
        for (feature, state) in [
            (Feature::Region, REGION_FREE),
            (Feature::Speed, SPEED_MAX),
            (Feature::Unrestricted, STATE_ON),
        ] {
            if capabilities.supports_set(feature, state)
                && let Err(UnlockError::Transport) =
                    self.set_checked(scsi, feature, state, Some(backend))
            {
                return Err(UnlockError::Transport);
            }
        }
        if !capabilities.supports_set(Feature::Encryption, STATE_OFF) {
            return Err(UnlockError::NotApplicable);
        }
        self.set_checked(scsi, Feature::Encryption, STATE_OFF, Some(backend))
            .map_err(|e| match e {
                UnlockError::Transport => e,
                _ => UnlockError::VidUnavailable,
            })
    }
}

impl Unlocker for FreemkvUnlocker {
    fn name(&self) -> &'static str {
        "freemkv"
    }

    /// Recognise the drive by its IDENTITY knock, lift riplock/region and open
    /// Unrestricted (best-effort), set Encryption=off (the actual unlock), and
    /// read the Volume ID with a bare `0xAD` (best-effort). `Some` when the
    /// Encryption=off set succeeded — the drive is unlocked whether or not the
    /// VID read did; `None` if it isn't supported freemkv firmware;
    /// `Err(Transport)` on a dead bus. `ctx` is unused: this unlocker
    /// self-identifies rather than matching on drive identity.
    fn unlock(
        &self,
        scsi: &mut dyn ScsiTransport,
        _ctx: &UnlockCtx,
    ) -> std::result::Result<Option<Unlocked>, UnlockError> {
        crate::fallthrough(self.full_unlock(scsi))
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
