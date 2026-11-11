//! Native Pioneer speed policy. No product-name checks, RAM writes or EEPROM saves.
//! Automatic quiet control off disables the adaptive quiet policy; it does not bypass
//! media/servo limits or establish measured throughput. MMC speed requests stay host-owned.
use crate::UnlockError;
use crate::scsi::{DataDirection, ScsiError, ScsiTransport, is_dead_bus};
use pioneer_optical::device::{Device, Error, Persistence, QuietDrive, WriteOutcome};
use pioneer_optical::drive::{Data, Transport};
use pioneer_optical::settings::{QuietMode, QuietState};

struct Adapter<'a>(&'a mut dyn ScsiTransport);
impl Transport for Adapter<'_> {
    type Error = ScsiError;
    fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, ScsiError> {
        let mut empty = [];
        let (direction, bytes) = match data {
            Data::None => (DataDirection::None, &mut empty[..]),
            Data::In(b) => (DataDirection::FromDevice, b),
            // QuietDrive is a no-data command. Never silently accept a future
            // codec change that introduces a data-out/persistent write here.
            Data::Out(_) => {
                return Err(ScsiError {
                    status: 2,
                    sense: Some([0; 32]),
                });
            }
        };
        let r = self.0.execute(cdb, direction, bytes, 5_000)?;
        if r.status != 0 {
            return Err(ScsiError {
                status: r.status,
                sense: Some(r.sense),
            });
        }
        Ok(r.bytes_transferred)
    }
    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
}

type Outcome = Result<WriteOutcome<QuietState, ScsiError>, Error<ScsiError>>;
// The codec calls mode 0 Standard; Pioneer implements it as AutoSeion off (FD).
// Performance (mode 1 / FE) still enables the adaptive quiet controller.
fn select(scsi: &mut dyn ScsiTransport) -> Outcome {
    Device::new(&mut Adapter(scsi)).set(QuietDrive, QuietMode::Standard, Persistence::Volatile)
}

pub(super) fn configure(scsi: &mut dyn ScsiTransport) -> Result<(), UnlockError> {
    match select(scsi) {
        Ok(WriteOutcome::Verified(state) | WriteOutcome::Unchanged(state)) => {
            tracing::info!(target: "freemkv::drive", phase = "pioneer_speed_policy",
                current = ?state.current, saved = ?state.saved,
                "Pioneer automatic quiet control off verified (volatile)");
        }
        Ok(WriteOutcome::Mismatch(state)) => {
            tracing::warn!(target: "freemkv::drive", phase = "pioneer_speed_policy",
                current = ?state.current, "Pioneer automatic quiet control off did not take effect; speed may remain limited");
        }
        Err(e) | Ok(WriteOutcome::Unverified(e)) => {
            tracing::warn!(target: "freemkv::drive", phase = "pioneer_speed_policy",
                error = ?e, "Pioneer automatic quiet control off unavailable or unverified; speed may remain limited");
            if matches!(e, Error::Transport { source, .. } if is_dead_bus(&source)) {
                return Err(UnlockError::Transport);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
