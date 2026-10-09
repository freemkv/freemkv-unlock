//! renesas — Renesas-platform detection (Pioneer + HL-DT-ST Renesas drives).
//!
//! Detection alone does not establish unlocked state. A supported firmware must
//! pass firmware and resident-payload integrity checks, then activation verification.
//! The protocol hook stays resident; activation restores its borrowed OEM callback.
//! VID retrieval is a separate, read-only operation.

use crate::UnlockError;
#[cfg(test)]
use crate::Unlocked;
use crate::scsi::{DataDirection, ScsiTransport, is_dead_bus};

/// The Renesas vendor identity block length (READ_BUFFER 0x02/0xF1).
const RB_F1_LEN: usize = pioneer_optical::IDENTITY_LEN;
/// The ASCII interface marker a Renesas controller returns at `[16..19]`.
const RENESAS_MARKER: &[u8] = b"SAT";
const RENESAS_MARKER_OFFSET: usize = 16;

/// `Ok(true)` if `scsi` is a Renesas-platform drive (Pioneer or HL-DT-ST
/// Renesas).
///
/// Issues the vendor READ_BUFFER 0x02/0xF1 probe: a Renesas controller serves
/// a 48-byte identity block whose bytes `[16..19]` are the ASCII `SAT`
/// interface tag. A rejection (CHECK CONDITION or `Err` with a sense) is
/// `Ok(false)`: not a Renesas drive.
///
/// `Err(Transport)` on a dead bus.
pub fn is_renesas(scsi: &mut dyn ScsiTransport) -> std::result::Result<bool, UnlockError> {
    let mut buf = [0u8; RB_F1_LEN];
    let cdb = pioneer_optical::cdb::vendor_identity();
    match scsi.execute(&cdb, DataDirection::FromDevice, &mut buf, 5_000) {
        Ok(r) => {
            let end = RENESAS_MARKER_OFFSET + RENESAS_MARKER.len();
            Ok(r.status == 0
                && (end..=buf.len()).contains(&r.bytes_transferred)
                && &buf[RENESAS_MARKER_OFFSET..end] == RENESAS_MARKER)
        }
        // Only a senseless transport-failure status is a dead bus; anything
        // else the transport reports as `Err` is the drive refusing.
        Err(e) => {
            if is_dead_bus(&e) {
                tracing::warn!(
                    target: "freemkv::disc",
                    phase = "renesas_probe_transport_fault",
                    "transport fault on the Renesas identity probe; aborting"
                );
                return Err(UnlockError::Transport);
            }
            tracing::debug!(
                target: "freemkv::disc",
                phase = "renesas_probe_rejected",
                status = e.status,
                "Renesas identity probe rejected by the drive; not a Renesas platform"
            );
            Ok(false)
        }
    }
}

// Selector 0x92 maps offset - 0x2000 to high CPU memory; no AAAA gate.
const VID_STATUS_CDB: [u8; 10] = [0x3c, 2, 0x92, 0, 0x0d, 0x3c, 0, 0, 1, 0];
const VID_CDB: [u8; 10] = [0x3c, 2, 0x92, 0, 0x0d, 0x20, 0, 0, 16, 0];

/// Read the hardware VID when its ready bit is set. Does not install a hook.
/// Returns `None` for an unavailable, rejected, short, or uniform VID response.
pub fn read_vid(
    scsi: &mut dyn ScsiTransport,
) -> std::result::Result<Option<[u8; 16]>, UnlockError> {
    // Mirror the OEM hardware-copy gate. Other status bits are not interpreted.
    let mut status = [0];
    let result = scsi.execute(
        &VID_STATUS_CDB,
        DataDirection::FromDevice,
        &mut status,
        5_000,
    );
    tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_status",
        cdb = ?VID_STATUS_CDB, requested = 1, ?result, payload = ?status,
        "Reading Renesas VID hardware status");
    match result {
        Ok(r) if r.status == 0 && r.bytes_transferred == 1 && status[0] & 2 != 0 => {}
        Err(e) if is_dead_bus(&e) => return Err(UnlockError::Transport),
        _ => return Ok(None),
    }
    let mut vid = [0u8; 16];
    let cdb = VID_CDB;
    let address = 0xffff_ed20u32;
    tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_request",
        address = format_args!("{address:#x}"), cdb = format_args!("{cdb:02x?}"), requested = vid.len(), "Reading VID from Renesas hardware registers");
    let result = match scsi.execute(&cdb, DataDirection::FromDevice, &mut vid, 5_000) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_error",
                address = format_args!("{address:#x}"), status = e.status, sense = ?e.sense,
                dead_bus = is_dead_bus(&e),
                "Renesas hardware VID read failed");
            return if is_dead_bus(&e) {
                Err(UnlockError::Transport)
            } else {
                Ok(None)
            };
        }
    };
    let rejection = if result.status != 0 {
        Some("scsi_status")
    } else if result.bytes_transferred != vid.len() {
        Some("transfer_length")
    } else if vid.iter().all(|&b| b == 0) {
        Some("all_zero")
    } else if vid.iter().all(|&b| b == 0xff) {
        Some("all_ff")
    } else {
        None
    };
    let valid = rejection.is_none();
    // Only show bytes the transport reports receiving, never buffer padding.
    let payload = &vid[..result.bytes_transferred.min(vid.len())];
    tracing::debug!(target: "freemkv::disc", phase = "renesas_vid_result",
        address = format_args!("{address:#x}"), status = result.status,
        bytes_transferred = result.bytes_transferred, sense = ?result.sense,
        payload = format_args!("{payload:02x?}"), valid, rejection,
        "Renesas hardware VID response");
    Ok(valid.then_some(vid))
}

pub(super) struct Backend {
    prepared: Option<hook::Prepared>,
    existing: bool,
    touched: bool,
}
impl Backend {
    pub(super) fn new() -> Self {
        Self {
            prepared: None,
            existing: false,
            touched: false,
        }
    }
}
impl super::Backend for Backend {
    fn command_timeout_ms(&self, feature: crate::protocol::Feature) -> u32 {
        if feature == crate::protocol::Feature::Encryption {
            // Includes the bounded reader drain and OEM media reacquisition.
            // An idle drive can need several seconds even when warm activation is fast.
            30_000
        } else {
            5_000
        }
    }
    fn prepare(
        &mut self,
        scsi: &mut dyn ScsiTransport,
        installed: bool,
    ) -> Result<(), UnlockError> {
        let prepared = hook::prepare(scsi, hook::operations::Operation::Suppress, installed)
            .map_err(|e| hook::preparation_error(e, installed))?;
        self.existing = installed;
        self.prepared = Some(prepared);
        Ok(())
    }
    fn install(
        &mut self,
        scsi: &mut dyn ScsiTransport,
        installed: bool,
    ) -> Result<(), UnlockError> {
        let prepared = self.prepared.as_ref().ok_or(UnlockError::NotApplicable)?;
        hook::check_prepared(scsi, prepared, installed)
            .map_err(|e| hook::preparation_error(e, installed))?;
        self.touched = true;
        if !installed {
            hook::stage(scsi, prepared).map_err(hook::transaction_error)?;
        }
        Ok(())
    }
    fn validate_set_reply(
        &self,
        reply: &crate::scsi::ScsiResult,
        data: &[u8],
    ) -> Result<(), UnlockError> {
        if reply.bytes_transferred == 64 && data == [0; 64] {
            Ok(())
        } else {
            Err(UnlockError::Transport)
        }
    }
    fn capabilities(&self) -> crate::protocol::Capabilities {
        crate::protocol::ProtocolIdentity::parse(&crate::protocol::pioneer_identity())
            .unwrap()
            .capabilities
    }
    fn verify(&self, scsi: &mut dyn ScsiTransport) -> Result<(), UnlockError> {
        let p = self.prepared.as_ref().ok_or(UnlockError::NotApplicable)?;
        hook::verify_state(scsi, p).map_err(hook::transaction_error)?;
        hook::verify_resident(scsi, p).map_err(hook::transaction_error)
    }
    fn finish(&mut self, scsi: &mut dyn ScsiTransport, success: bool) -> Result<(), UnlockError> {
        if !self.touched {
            return Ok(());
        }
        if let Some(p) = &self.prepared {
            let verified = success && hook::verify_resident(scsi, p).is_ok();
            if !verified {
                if !self.existing {
                    hook::cleanup(scsi, p).map_err(hook::transaction_error)?;
                }
                return Err(UnlockError::Transport);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
fn unlock(scsi: &mut dyn ScsiTransport) -> Result<Option<Unlocked>, UnlockError> {
    if !is_renesas(scsi)? {
        return Ok(None);
    }
    crate::fallthrough(hook::unlock(scsi).and_then(|()| {
        Ok(Unlocked {
            vid: read_vid(scsi)?,
            bus_key: None,
        })
    }))
}

#[cfg(test)]
#[path = "renesas/mod_tests.rs"]
mod mod_tests;

mod hook {
    use pioneer_optical::firmware::{abi, layout};
    // Firmware writes and activation are serialized in a critical span.

    use crate::scsi::{DataDirection, ScsiTransport};
    use anyhow::{Context, Result, ensure};
    use layout::Range;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    const TIMEOUT_MS: u32 = 10_000;
    const MAX_PAYLOAD: usize = 65536;

    pub fn sha256(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct Guard {
        pub cpu_address: u32,
        pub expected: Vec<u8>,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct Profile {
        pub normal_address: u32,
        pub normal_length: u32,
        pub normal_sha256: String,
        pub controller_cpu_base: u32,
        pub pointer_address: u32,
        pub original_table: u32,
        pub write_pointer_address: u32,
        pub write_original_table: u32,
        pub table_length: u32,
        pub main_callback_offset: u32,
        pub reserved_windows: Vec<Range>,
        pub occupied: Vec<Range>,
        pub guards: Vec<Guard>,
        pub ownership_evidence: String,
        pub write_path_evidence: String,
    }

    #[derive(Debug, Serialize)]
    pub struct FreeSpace {
        pub cpu: Range,
        pub length: u32,
        pub controller_offset: u32,
        pub firmware_sha256: String,
        pub ownership_evidence: String,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct Relocation {
        pub offset: usize,
        pub addend: u32,
        pub controller_relative: bool,
    }

    /// Developer-assembled bytes, a complete OEM table copy, and explicit relocations.
    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct Trampoline {
        /// Firmware image from which all absolute call targets were derived.
        pub source_sha256: String,
        pub bytes: Vec<u8>,
        pub alignment: u32,
        pub wrapper_offset: u32,
        pub table_offset: u32,
        pub vid_wrapper_offset: u32,
        pub vid_table_offset: u32,
        pub relocations: Vec<Relocation>,
        /// One tri-state data byte; code and callback table remain immutable.
        #[serde(default)]
        pub mutable_state_offset: Option<usize>,
    }

    #[derive(Debug, Serialize)]
    pub struct CdbReply {
        pub cdb: Vec<u8>,
        pub status: u8,
        pub transferred: usize,
        pub sense: Vec<u8>,
        pub data: Vec<u8>,
    }

    /// One raw call through the caller's libfreemkv connection. No retry or status masking.
    pub fn generic_cdb(
        connection: &mut dyn ScsiTransport,
        cdb: &[u8],
        direction: DataDirection,
        mut data: Vec<u8>,
    ) -> Result<CdbReply> {
        ensure!(
            [6, 10, 12, 16].contains(&cdb.len()),
            "unsupported CDB length"
        );
        ensure!(data.len() <= 4096usize, "transfer exceeds transport limit");
        ensure!(
            direction != DataDirection::None || data.is_empty(),
            "no-data command has a buffer"
        );
        let result = connection
            .execute(cdb, direction, &mut data, TIMEOUT_MS)
            .map_err(command_error)?;
        ensure!(
            result.bytes_transferred <= data.len(),
            "invalid transport transfer count"
        );
        if direction == DataDirection::FromDevice {
            data.truncate(result.bytes_transferred);
        } else {
            data.clear();
        }
        Ok(CdbReply {
            cdb: cdb.to_vec(),
            status: result.status,
            transferred: result.bytes_transferred,
            sense: result.sense.to_vec(),
            data,
        })
    }

    #[cfg(test)]
    fn exact(reply: CdbReply, expected: usize) -> Result<Vec<u8>> {
        ensure!(
            reply.status == 0 && reply.transferred == expected,
            "CDB {:02x?}: status={:02x}, count={} expected={}, sense={:02x?}",
            reply.cdb,
            reply.status,
            reply.transferred,
            expected,
            reply.sense
        );
        Ok(reply.data)
    }

    fn address(profile: &Profile, cpu: u32, length: u32) -> Result<(u8, u32)> {
        let r = Range::new(cpu, length)?;
        if cpu >= profile.controller_cpu_base {
            let offset = cpu - profile.controller_cpu_base;
            ensure!(
                offset
                    .checked_add(length)
                    .is_some_and(|end| end <= 0x400000),
                "outside controller RAM"
            );
            Ok((0x93, offset))
        } else {
            ensure!(r.end() <= 0x880000, "outside supported CPU read range");
            Ok((0xb0, cpu))
        }
    }

    struct OpticalTransport<'a>(&'a mut dyn ScsiTransport);
    impl pioneer_optical::drive::Transport for OpticalTransport<'_> {
        type Error = anyhow::Error;
        fn exec(&mut self, cdb: &[u8], data: pioneer_optical::drive::Data<'_>) -> Result<usize> {
            use pioneer_optical::drive::Data;
            let (direction, mut bytes) = match &data {
                Data::None => (DataDirection::None, Vec::new()),
                Data::In(b) => (DataDirection::FromDevice, vec![0; b.len()]),
                Data::Out(b) => (DataDirection::ToDevice, b.to_vec()),
            };
            let result = self
                .0
                .execute(cdb, direction, &mut bytes, TIMEOUT_MS)
                .map_err(command_error)?;
            ensure!(
                result.status == 0,
                "diagnostic command rejected: status={}, sense={:02x?}",
                result.status,
                result.sense
            );
            ensure!(
                result.bytes_transferred <= bytes.len(),
                "invalid transfer count"
            );
            if let Data::In(out) = data {
                out[..result.bytes_transferred].copy_from_slice(&bytes[..result.bytes_transferred]);
            }
            Ok(result.bytes_transferred)
        }
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
    }

    fn writable_ram(cpu: u32, length: u32) -> bool {
        length != 0
            && cpu.checked_add(length).is_some_and(|end| {
                (cpu > 0 && end <= 0x8000) || (cpu >= 0xa00000 && end <= 0xe00000)
            })
    }

    fn memory(
        connection: &mut dyn ScsiTransport,
        profile: &Profile,
        cpu: u32,
        bytes: &mut [u8],
        write: bool,
    ) -> Result<()> {
        let total: u32 = bytes.len().try_into()?;
        address(profile, cpu, total)?;
        if write {
            ensure!(
                writable_ram(cpu, total),
                "installer writes are restricted to RAM"
            );
        }
        let (selector, offset) = address(profile, cpu, total)?;
        let mut transport = OpticalTransport(connection);
        let data = if write {
            pioneer_optical::drive::Data::Out(bytes)
        } else {
            pioneer_optical::drive::Data::In(bytes)
        };
        pioneer_optical::drive::diagnostic_memory(&mut transport, selector, offset, data).map_err(
            |e| match e {
                pioneer_optical::drive::Error::Transport(e) => e,
                other => anyhow::anyhow!("diagnostic memory transfer: {other}"),
            },
        )?;
        Ok(())
    }

    pub(crate) fn read(
        connection: &mut dyn ScsiTransport,
        profile: &Profile,
        cpu: u32,
        length: u32,
    ) -> Result<Vec<u8>> {
        ensure!(length > 0 && length <= 0x400000, "read size out of bounds");
        let mut bytes = vec![0; length as usize];
        memory(connection, profile, cpu, &mut bytes, false)?;
        Ok(bytes)
    }

    fn guards(connection: &mut dyn ScsiTransport, profile: &Profile) -> Result<()> {
        ensure!(!profile.guards.is_empty(), "runtime map guards required");
        for guard in &profile.guards {
            ensure!(
                !guard.expected.is_empty() && guard.expected.len() <= 4096,
                "invalid guard length"
            );
            ensure!(
                read(
                    connection,
                    profile,
                    guard.cpu_address,
                    guard.expected.len().try_into()?
                )? == guard.expected,
                "runtime map changed at {:#x}",
                guard.cpu_address
            );
        }
        Ok(())
    }

    fn validate(profile: &Profile) -> Result<()> {
        ensure!(
            !profile.ownership_evidence.trim().is_empty(),
            "reviewed RAM ownership evidence required"
        );
        ensure!(
            !profile.write_path_evidence.trim().is_empty(),
            "reviewed RAM write-path evidence required"
        );
        ensure!(
            profile.normal_length >= 0x1100 && profile.normal_length <= 0x400000,
            "invalid Normal size"
        );
        ensure!(
            profile
                .normal_address
                .checked_add(profile.normal_length)
                .is_some_and(|e| e <= 0x880000),
            "Normal outside CPU read map"
        );
        ensure!(
            profile.controller_cpu_base == 0xa00000,
            "unsupported controller alias; add a reviewed backend"
        );
        ensure!(
            profile.pointer_address.is_multiple_of(2)
                && profile
                    .pointer_address
                    .checked_add(4)
                    .is_some_and(|e| e <= 0x8000),
            "object pointer must be in low RAM"
        );
        ensure!(
            profile.table_length == 40 && profile.main_callback_offset == 0x24,
            "unsupported callback table shape"
        );
        ensure!(
            profile.write_pointer_address.is_multiple_of(2)
                && profile
                    .write_pointer_address
                    .checked_add(4)
                    .is_some_and(|e| e <= 0x8000)
                && profile.write_pointer_address != profile.pointer_address,
            "invalid independent WRITE BUFFER object"
        );
        let normal = Range::new(profile.normal_address, profile.normal_length)?;
        ensure!(
            normal.contains(&Range::new(profile.original_table, profile.table_length)?),
            "OEM table outside bound Normal image"
        );
        ensure!(
            normal.contains(&Range::new(
                profile.write_original_table,
                profile.table_length
            )?),
            "WRITE BUFFER table outside image"
        );
        let ram = Range::new(profile.controller_cpu_base, 0x400000)?;
        ensure!(
            !profile.reserved_windows.is_empty()
                && profile
                    .reserved_windows
                    .iter()
                    .all(|w| w.start() < w.end() && ram.contains(w)),
            "reserved windows must be controller RAM"
        );
        Ok(())
    }

    /// Validate the live firmware and runtime guards, then select a reviewed reservation.
    pub fn find_free_space(
        connection: &mut dyn ScsiTransport,
        profile: &Profile,
        size: u32,
        alignment: u32,
    ) -> Result<FreeSpace> {
        ensure!(
            size > 0 && size as usize <= MAX_PAYLOAD,
            "invalid payload size"
        );
        let mut space = find_free_spaces(connection, profile, alignment)?
            .into_iter()
            .find(|space| space.cpu.length() >= size)
            .context(
                "no region fits; place complete H8 blocks across the returned free-space list",
            )?;
        space.cpu = Range::new(space.cpu.start(), size)?;
        space.length = size;
        Ok(space)
    }

    /// All structurally available regions after live firmware/map checks.
    pub fn find_free_spaces(
        connection: &mut dyn ScsiTransport,
        profile: &Profile,
        alignment: u32,
    ) -> Result<Vec<FreeSpace>> {
        validate(profile)?;
        let image = read(
            connection,
            profile,
            profile.normal_address,
            profile.normal_length,
        )?;
        ensure!(
            sha256(&image) == profile.normal_sha256,
            "live firmware hash mismatch"
        );
        let layout = layout::inspect(&image)?;
        ensure!(
            layout.image_base == Some(profile.normal_address)
                && !layout.overlay_ranges.is_empty()
                && !layout.buffer_tables.is_empty(),
            "unrecognized firmware memory layout"
        );
        guards(connection, profile)?;
        let derived = discovery::profile(&image)?;
        ensure!(
            profile.pointer_address == derived.pointer_address
                && profile.original_table == derived.original_table
                && profile.table_length == derived.table_length
                && profile.write_pointer_address == derived.write_pointer_address
                && profile.write_original_table == derived.write_original_table,
            "profile callback addresses disagree with live firmware discovery"
        );
        ensure!(
            profile
                .reserved_windows
                .iter()
                .all(|w| derived.reserved_windows.iter().any(|d| d.contains(w))),
            "profile windows exceed the structurally discovered gap"
        );
        guards(connection, &derived)?;
        let mut occupied = derived.occupied;
        occupied.extend(profile.occupied.clone());
        for guard in profile.guards.iter().chain(derived.guards.iter()) {
            occupied.push(Range::new(
                guard.cpu_address,
                guard.expected.len().try_into()?,
            )?);
        }
        occupied.extend(layout.overlay_ranges);
        // Treat every concrete OEM table interval as occupied, including alternate modes.
        for table in layout.buffer_tables {
            for entry in table.entries {
                if let Some(range) = entry.range(profile.controller_cpu_base, 0x400000)? {
                    occupied.push(range);
                }
            }
        }
        Ok(
            layout::free_ranges(&profile.reserved_windows, &occupied, alignment)?
                .into_iter()
                .map(|cpu| FreeSpace {
                    length: cpu.length(),
                    controller_offset: cpu.start() - profile.controller_cpu_base,
                    cpu,
                    firmware_sha256: profile.normal_sha256.clone(),
                    ownership_evidence: profile.ownership_evidence.clone(),
                })
                .collect(),
        )
    }

    #[derive(Debug)]
    struct DeadTransport;
    impl std::fmt::Display for DeadTransport {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Renesas transport failed")
        }
    }
    impl std::error::Error for DeadTransport {}
    fn command_error(e: crate::scsi::ScsiError) -> anyhow::Error {
        if crate::scsi::is_dead_bus(&e) {
            anyhow::Error::new(DeadTransport)
        } else {
            anyhow::anyhow!("drive rejected command: {e:?}")
        }
    }

    pub(super) struct Prepared {
        #[cfg(test)]
        operation: operations::Operation,
        pub(super) profile: Profile,
        sites: operations::Sites,
        allocation: Range,
        original: Vec<u8>,
        payload: Vec<u8>,
        installed_pointer: Vec<u8>,
        vid_installed_pointer: Vec<u8>,
    }
    pub(super) fn prepare(
        connection: &mut dyn ScsiTransport,
        op: operations::Operation,
        existing: bool,
    ) -> Result<Prepared> {
        discovery::enable_diagnostic_reads(connection)?;
        let image = discovery::load_normal(connection)?;
        let (trampoline, sites) = operations::build(&image, op)?;
        let mut profile = discovery::profile(&image)?;
        profile.guards.push(sites.acquisition.clone());
        profile.guards.push(sites.reset.clone());
        for (at, length) in [
            (sites.vid.slot, 4),
            (sites.security_slot, 4),
            (sites.acquisition.cpu_address, 4),
            (sites.reset.cpu_address, 4),
            (sites.loaded, 1),
            (sites.checked, 1),
            (sites.result, 1),
            (sites.read_engine_state, 1),
            (sites.buffers[0], 16),
            (sites.buffers[1], 16),
        ] {
            profile.occupied.push(Range::new(at, length)?);
        }
        let space = find_free_space(
            connection,
            &profile,
            trampoline.bytes.len() as u32,
            trampoline.alignment,
        )?;
        ensure!(
            read(connection, &profile, profile.pointer_address, 4)?
                == if existing {
                    (space.cpu.start() + trampoline.table_offset).to_be_bytes()
                } else {
                    profile.original_table.to_be_bytes()
                },
            "READ BUFFER ownership mismatch"
        );
        ensure!(
            read(connection, &profile, profile.write_pointer_address, 4)?
                == profile.write_original_table.to_be_bytes(),
            "WRITE BUFFER already hooked"
        );
        let vid_installed_pointer = (space.cpu.start() + trampoline.vid_table_offset)
            .to_be_bytes()
            .to_vec();
        ensure!(
            read(connection, &profile, sites.vid.slot, 4)?
                == if existing {
                    vid_installed_pointer.clone()
                } else {
                    sites.vid.table.to_be_bytes().to_vec()
                },
            "READ DISC STRUCTURE ownership mismatch"
        );
        let mut table = read(connection, &profile, profile.original_table, 40)?;
        ensure!(
            table[0x14..0x18] == [0; 4] && table[0x1e..0x22] == [0; 4],
            "unsupported OEM adjustments"
        );
        let mut payload = trampoline.bytes;
        for r in trampoline.relocations {
            let base = if r.controller_relative {
                space.controller_offset
            } else {
                space.cpu.start()
            };
            let value = base.checked_add(r.addend).context("relocation overflow")?;
            payload
                .get_mut(r.offset..r.offset + 4)
                .context("relocation outside payload")?
                .copy_from_slice(&value.to_be_bytes());
        }
        table[0x24..0x28]
            .copy_from_slice(&(space.cpu.start() + trampoline.wrapper_offset).to_be_bytes());
        let at = trampoline.table_offset as usize;
        payload
            .get_mut(at..at + 40)
            .context("table outside payload")?
            .copy_from_slice(&table);
        let mut vid_table = read(connection, &profile, sites.vid.table, 40)?;
        ensure!(
            vid_table[0x14..0x18] == [0; 4] && vid_table[0x1e..0x22] == [0; 4],
            "unsupported VID object adjustments"
        );
        vid_table[0x24..0x28]
            .copy_from_slice(&(space.cpu.start() + trampoline.vid_wrapper_offset).to_be_bytes());
        let at = trampoline.vid_table_offset as usize;
        payload
            .get_mut(at..at + 40)
            .context("VID table outside payload")?
            .copy_from_slice(&vid_table);
        let original = read(
            connection,
            &profile,
            space.cpu.start(),
            payload.len() as u32,
        )?;
        ensure!(
            read(
                connection,
                &profile,
                space.cpu.start(),
                payload.len() as u32
            )? == original,
            "allocation not stable"
        );
        if existing {
            ensure!(
                original == payload,
                "resident payload differs from this implementation"
            );
        }
        let security = read(connection, &profile, sites.security_slot, 4)?;
        ensure!(
            security == sites.security_table.to_be_bytes()
                || (existing
                    && security
                        == sites
                            .policy_table(space.cpu.start(), payload.len())
                            .to_be_bytes()),
            "security table ownership mismatch"
        );
        Ok(Prepared {
            #[cfg(test)]
            operation: op,
            sites,
            profile,
            allocation: space.cpu.clone(),
            original,
            payload,
            installed_pointer: (space.cpu.start() + trampoline.table_offset)
                .to_be_bytes()
                .to_vec(),
            vid_installed_pointer,
        })
    }
    pub(super) fn verify_state(connection: &mut dyn ScsiTransport, p: &Prepared) -> Result<()> {
        // Software loaded-key, cache-valid, cache-result. Not hardware attestation.
        ensure!(
            read(connection, &p.profile, p.sites.loaded, 1)? == [0]
                && read(connection, &p.profile, p.sites.checked, 1)? == [1]
                && read(connection, &p.profile, p.sites.result, 1)? == [0],
            "activation state verification failed"
        );
        Ok(())
    }
    pub(super) fn cleanup(connection: &mut dyn ScsiTransport, p: &Prepared) -> Result<()> {
        let profile = &p.profile;
        // Always detach first, even after an uncertain/partial activation-pointer write.
        // Exclusive transport ownership and the pre-write check establish ownership.
        let mut pointer = profile.original_table.to_be_bytes();
        memory(
            connection,
            profile,
            profile.pointer_address,
            &mut pointer,
            true,
        )?;
        ensure!(
            read(connection, profile, profile.pointer_address, 4)? == pointer,
            "hook detach failed"
        );
        let mut vid_original = p.sites.vid.table.to_be_bytes();
        memory(
            connection,
            profile,
            p.sites.vid.slot,
            &mut vid_original,
            true,
        )?;
        ensure!(
            read(connection, profile, p.sites.vid.slot, 4)? == vid_original,
            "VID hook detach failed"
        );
        ensure!(
            read(connection, profile, profile.write_pointer_address, 4)?
                == profile.write_original_table.to_be_bytes(),
            "independent restoration path changed"
        );
        // If nested execution did not restore its callback, do not free that payload.
        guards(connection, profile)?;
        restore_policy(connection, p)?;
        let mut original = p.original.clone();
        memory(
            connection,
            profile,
            p.allocation.start(),
            &mut original,
            true,
        )?;
        ensure!(
            read(
                connection,
                profile,
                p.allocation.start(),
                original.len() as u32
            )? == original,
            "allocation restore failed"
        );
        Ok(())
    }
    pub(super) fn preparation_error(e: anyhow::Error, existing: bool) -> crate::UnlockError {
        tracing::debug!(target:"freemkv::disc", error=%e, "Pioneer preparation declined");
        if existing || e.is::<DeadTransport>() {
            crate::UnlockError::Transport
        } else {
            crate::UnlockError::NotApplicable
        }
    }
    pub(super) fn transaction_error(e: anyhow::Error) -> crate::UnlockError {
        tracing::error!(target:"freemkv::disc", error=%e, "Pioneer transaction failed");
        crate::UnlockError::Transport
    }
    pub(super) fn check_prepared(
        connection: &mut dyn ScsiTransport,
        p: &Prepared,
        existing: bool,
    ) -> Result<()> {
        // Recheck all ownership immediately before the first write.
        guards(connection, &p.profile)?;
        let security = read(connection, &p.profile, p.sites.security_slot, 4)?;
        ensure!(
            security == p.sites.security_table.to_be_bytes()
                || (existing
                    && security
                        == p.sites
                            .policy_table(p.allocation.start(), p.payload.len())
                            .to_be_bytes()),
            "security table ownership changed"
        );
        ensure!(
            read(connection, &p.profile, p.profile.pointer_address, 4)?
                == if existing {
                    p.installed_pointer.clone()
                } else {
                    p.profile.original_table.to_be_bytes().to_vec()
                },
            "hook ownership changed"
        );
        ensure!(
            read(connection, &p.profile, p.profile.write_pointer_address, 4)?
                == p.profile.write_original_table.to_be_bytes(),
            "write ownership changed"
        );
        ensure!(
            read(connection, &p.profile, p.sites.vid.slot, 4)?
                == if existing {
                    p.vid_installed_pointer.clone()
                } else {
                    p.sites.vid.table.to_be_bytes().to_vec()
                },
            "VID hook ownership changed"
        );
        ensure!(
            read(
                connection,
                &p.profile,
                p.allocation.start(),
                p.original.len() as u32
            )? == p.original,
            "allocation changed"
        );
        Ok(())
    }
    pub(super) fn stage(connection: &mut dyn ScsiTransport, p: &Prepared) -> Result<()> {
        let mut payload = p.payload.clone();
        memory(
            connection,
            &p.profile,
            p.allocation.start(),
            &mut payload,
            true,
        )?;
        ensure!(
            read(
                connection,
                &p.profile,
                p.allocation.start(),
                payload.len() as u32
            )? == payload,
            "payload verification failed"
        );
        let mut vid_pointer = p.vid_installed_pointer.clone();
        memory(
            connection,
            &p.profile,
            p.sites.vid.slot,
            &mut vid_pointer,
            true,
        )?;
        ensure!(
            read(connection, &p.profile, p.sites.vid.slot, 4)? == vid_pointer,
            "VID installation verification failed"
        );
        let mut pointer = p.installed_pointer.clone();
        memory(
            connection,
            &p.profile,
            p.profile.pointer_address,
            &mut pointer,
            true,
        )?;
        ensure!(
            read(connection, &p.profile, p.profile.pointer_address, 4)? == pointer,
            "installation verification failed"
        );
        Ok(())
    }
    fn restore_policy(connection: &mut dyn ScsiTransport, p: &Prepared) -> Result<()> {
        let current = read(connection, &p.profile, p.sites.security_slot, 4)?;
        let mut original = p.sites.security_table.to_be_bytes();
        let installed = p
            .sites
            .policy_table(p.allocation.start(), p.payload.len())
            .to_be_bytes();
        ensure!(
            current == original || current == installed,
            "security table ownership changed"
        );
        if current == installed {
            memory(
                connection,
                &p.profile,
                p.sites.security_slot,
                &mut original,
                true,
            )?;
            ensure!(
                read(connection, &p.profile, p.sites.security_slot, 4)? == original,
                "security table restoration failed"
            );
        }
        Ok(())
    }
    pub(super) fn verify_resident(connection: &mut dyn ScsiTransport, p: &Prepared) -> Result<()> {
        ensure!(
            read(connection, &p.profile, p.sites.security_slot, 4)?
                == p.sites
                    .policy_table(p.allocation.start(), p.payload.len())
                    .to_be_bytes(),
            "persistent suppression missing"
        );
        guards(connection, &p.profile)?;
        ensure!(
            read(connection, &p.profile, p.profile.pointer_address, 4)? == p.installed_pointer,
            "resident pointer changed"
        );
        ensure!(
            read(connection, &p.profile, p.sites.vid.slot, 4)? == p.vid_installed_pointer,
            "resident VID pointer changed"
        );
        ensure!(
            read(connection, &p.profile, p.profile.write_pointer_address, 4)?
                == p.profile.write_original_table.to_be_bytes(),
            "write path changed"
        );
        ensure!(
            read(
                connection,
                &p.profile,
                p.allocation.start(),
                p.payload.len() as u32
            )? == p.payload,
            "resident payload changed"
        );
        Ok(())
    }
    #[cfg(test)]
    fn transact(connection: &mut dyn ScsiTransport, p: &Prepared) -> Result<Vec<u8>> {
        check_prepared(connection, p, false)?;
        let activated = (|| -> Result<Vec<u8>> {
            stage(connection, p)?;
            let op = p.operation;
            let response = exact(
                generic_cdb(
                    connection,
                    &op.cdb(),
                    DataDirection::FromDevice,
                    vec![0; op.length()],
                )?,
                op.length(),
            )?;
            if matches!(op, operations::Operation::Suppress) {
                ensure!(response == vec![0; 64], "unexpected activation response");
                verify_state(connection, p)?;
            }
            Ok(response)
        })();
        let restored = cleanup(connection, p);
        // Any post-write uncertainty is fatal to this drive session, never fallthrough.
        ensure!(
            restored.is_ok(),
            "restoration uncertain: {restored:?}; activation error={:?}",
            activated.as_ref().err()
        );
        let response = activated?;
        if matches!(p.operation, operations::Operation::Suppress) {
            verify_state(connection, p)?;
        }
        Ok(response)
    }

    #[cfg(test)]
    fn run(
        connection: &mut dyn ScsiTransport,
        operation: operations::Operation,
    ) -> std::result::Result<Vec<u8>, crate::UnlockError> {
        let prepared = prepare(connection, operation, false).map_err(|e| {
            tracing::debug!(target:"freemkv::disc", error=%e,"Renesas hook preparation declined");
            if e.is::<DeadTransport>() {
                crate::UnlockError::Transport
            } else {
                crate::UnlockError::NotApplicable
            }
        })?;
        finish(connection, &prepared)
    }

    #[cfg(test)]
    fn finish(
        connection: &mut dyn ScsiTransport,
        prepared: &Prepared,
    ) -> std::result::Result<Vec<u8>, crate::UnlockError> {
        let response = {
            let mut critical = crate::scsi::CriticalGuard::enter(connection)
                .map_err(|_| crate::UnlockError::Transport)?;
            transact(&mut *critical,prepared).map_err(|e|{
            tracing::error!(target:"freemkv::disc",error=%e,"Renesas activation transaction failed; stop drive use");
            crate::UnlockError::Transport
        })?
        };
        // Deliver a cancellation deferred during staging/activation/restoration.
        connection
            .pause(std::time::Duration::ZERO)
            .map_err(|_| crate::UnlockError::Transport)?;
        Ok(response)
    }

    #[cfg(test)]
    pub(super) fn unlock(
        connection: &mut dyn ScsiTransport,
    ) -> std::result::Result<(), crate::UnlockError> {
        run(connection, operations::Operation::Suppress).map(|_| ())
    }
    #[cfg(test)]
    mod transaction_tests {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/freemkv/renesas/transaction_tests.rs"
        ));
    }

    mod discovery {
        use crate::freemkv::renesas::hook::{Guard, Profile, generic_cdb, layout, sha256};
        use crate::scsi::{DataDirection, ScsiTransport};
        use anyhow::{Context, Result, ensure};
        pub(super) use pioneer_optical::firmware::callbacks::opcode_site;
        pub(super) fn hook_site(
            image: &[u8],
            base: u32,
        ) -> Result<pioneer_optical::firmware::callbacks::OpcodeSite> {
            let site = pioneer_optical::firmware::callbacks::read_buffer_site(image, base)?;
            let check = (site.check_address - base) as usize;
            let prepare = (site.prepare_address - base) as usize;
            ensure!(
                image.get(check..check + 2) == Some(&[0x54, 0x70]),
                "unsupported READ BUFFER check callback"
            );
            ensure!(
                image.get(prepare..prepare + 4) == Some(&[0x18, 0x88, 0x54, 0x70]),
                "unsupported READ BUFFER preparation callback"
            );
            Ok(site)
        }
        /// Derive an audit profile from the current decoded image; no address database.
        pub fn profile(image: &[u8]) -> Result<Profile> {
            let layout = layout::inspect(image)?;
            ensure!(
                !layout.structural_gaps.is_empty(),
                "no corroborated global-data/buffer gap"
            );
            let base = layout.image_base.context("no COMP base")?;
            let site = hook_site(image, base)?;
            let write = opcode_site(image, base, 0x3b)?;
            let mut occupied = layout.overlay_ranges;
            // Reserve all memory up to the last guard, not just initialized byte runs.
            let last = layout.global_canaries.iter().max().context("no canaries")? + 2;
            occupied.push(layout::Range::from_bounds(0xa00000, last)?);
            Ok(Profile {
        normal_address:base,normal_length:image.len().try_into()?,normal_sha256:sha256(image),
        controller_cpu_base:0xa00000,pointer_address:site.object_address,original_table:site.table_address,
        write_pointer_address:write.object_address,write_original_table:write.table_address,
        table_length:40,main_callback_offset:0x24,reserved_windows:layout.structural_gaps,
        occupied,guards:layout.global_canaries.into_iter().map(|cpu_address| Guard{cpu_address,expected:vec![0xa5,0xa5]}).collect(),
        ownership_evidence:"Derived global-data end: initializer copy end equals final 16-bit canary; upper bound is first OEM buffer; all recognized buffer maps excluded. Temporary allocation candidate, not a permanent RAM reservation.".into(),
        write_path_evidence:"Address discovery only. The stock payload builders additionally validate READ/WRITE helper call relationships; this field is descriptive, not an authorization bypass.".into(),
    })
        }

        /// Enable diagnostic reads using pioneer-optical's volatile vendor knock.
        /// This is separate from read-only detection so callers control session setup.
        pub fn enable_diagnostic_reads(connection: &mut dyn ScsiTransport) -> Result<()> {
            let reply = generic_cdb(
                connection,
                &pioneer_optical::cdb::knock(),
                DataDirection::None,
                vec![],
            )?;
            ensure!(
                reply.status == 0 && reply.transferred == 0,
                "diagnostic-read knock refused: {reply:?}"
            );
            Ok(())
        }

        /// Read the protocol Normal component from an already selected connection.
        pub fn load_normal(connection: &mut dyn ScsiTransport) -> Result<Vec<u8>> {
            let reply = generic_cdb(
                connection,
                &pioneer_optical::cdb::read_memory(0x410000, 256),
                DataDirection::FromDevice,
                vec![0; 256],
            )?;
            ensure!(
                reply.status == 0 && reply.transferred == 256,
                "Normal header read failed: {reply:?}"
            );
            ensure!(reply.data.starts_with(b"PIONEER "), "Normal header absent");
            let n = h8_asm::image::read_u32(&reply.data, 20).context("truncated Normal header")?;
            ensure!((0x1100..=0x3f0000).contains(&n), "invalid Normal size");
            let mut image = Vec::with_capacity(n as usize);
            let chunk = 4096usize;
            ensure!(chunk > 0, "zero transport capacity");
            while image.len() < n as usize {
                let len = chunk.min(n as usize - image.len());
                let cdb =
                    pioneer_optical::cdb::read_memory(0x410000 + image.len() as u32, len as u32);
                let reply = generic_cdb(connection, &cdb, DataDirection::FromDevice, vec![0; len])?;
                ensure!(
                    reply.status == 0 && reply.transferred == len,
                    "Normal body read failed: {reply:?}"
                );
                image.extend(reply.data);
            }
            Ok(image)
        }
    }

    mod firmware {
        //! Small H8S wrapper. All firmware call targets are discovered from this image.
        use crate::freemkv::renesas::hook::discovery;
        use anyhow::{Context, Result, ensure};
        use h8_asm::Asm;
        pub(super) use h8_asm::isa::{Ea, Insn, Operand, Reg, Size};

        pub(super) fn encode(insn: Insn) -> Result<Vec<u8>> {
            h8_asm::isa::encode_insn(insn, h8_asm::Target::H8S2000, h8_asm::Mode::Advanced)
                .map_err(|e| anyhow::anyhow!("H8S encoding {insn:?}: {e:?}"))
        }

        pub(super) fn instruction(a: &mut Asm, insn: Insn) -> Result<()> {
            emit(a, &encode(insn)?)
        }

        pub(super) fn emit_op(
            a: &mut Asm,
            name: &'static str,
            size: Option<Size>,
            source: Operand,
            dest: Operand,
        ) -> Result<()> {
            instruction(a, Insn::new(name, size, [source, dest, Operand::None]))
        }

        pub(super) fn push(a: &mut Asm, r: u8) -> Result<()> {
            emit_op(
                a,
                "MOV",
                Some(Size::Long),
                Operand::Register(Reg::Long(r)),
                Operand::Address(Ea::PreDecrement(Reg::Long(7))),
            )
        }

        pub(super) fn pop(a: &mut Asm, r: u8) -> Result<()> {
            emit_op(
                a,
                "MOV",
                Some(Size::Long),
                Operand::Address(Ea::PostIncrement(Reg::Long(7))),
                Operand::Register(Reg::Long(r)),
            )
        }

        pub(super) fn cdb_byte(a: &mut Asm, offset: usize) -> Result<()> {
            emit_op(
                a,
                "MOV",
                Some(Size::Byte),
                Operand::Address(Ea::Displacement {
                    base: Reg::Long(1),
                    value: offset.try_into()?,
                    bits: 16,
                }),
                Operand::Register(Reg::Byte(10)),
            )
        }

        pub(super) fn compare_byte(a: &mut Asm, value: u8) -> Result<()> {
            emit_op(
                a,
                "CMP",
                Some(Size::Byte),
                Operand::Immediate {
                    value: value.into(),
                    bits: 8,
                },
                Operand::Register(Reg::Byte(10)),
            )
        }

        pub(crate) fn abs(opcode: u8, addr: u32) -> Result<[u8; 4]> {
            ensure!(
                addr < 0x1000000 && addr.is_multiple_of(2),
                "invalid H8 code address"
            );
            let mnemonic = match opcode {
                0x5e => "JSR",
                0x5a => "JMP",
                _ => anyhow::bail!("unsupported absolute control transfer"),
            };
            encode(Insn::new(
                mnemonic,
                None,
                [
                    Operand::Address(Ea::Absolute {
                        value: addr,
                        bits: 24,
                    }),
                    Operand::None,
                    Operand::None,
                ],
            ))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("unexpected control-transfer width"))
        }

        pub(crate) fn emit(asm: &mut Asm, bytes: &[u8]) -> Result<()> {
            asm.instruction(bytes)
                .map_err(|e| anyhow::anyhow!("H8 instruction {:02x?}: {e:?}", bytes))
        }

        pub(crate) fn targets(image: &[u8]) -> Result<(u32, u32, u32)> {
            let layout = crate::freemkv::renesas::hook::layout::inspect(image)?;
            let base = layout.image_base.context("no image base")?;
            let site = discovery::hook_site(image, base)?;
            let helper = crate::freemkv::renesas::hook::abi::memory_call(
                image,
                base,
                site.main_address,
                0x93,
                false,
            )?;
            let invalid =
                crate::freemkv::renesas::hook::abi::controller_error(image, base, helper)?;
            Ok((site.main_address, helper, invalid))
        }

        pub(crate) fn write_paths(image: &[u8], main: u32, controller_helper: u32) -> Result<()> {
            let base = crate::freemkv::renesas::hook::layout::inspect(image)?
                .image_base
                .context("no image base")?;
            let write = discovery::opcode_site(image, base, 0x3b)?;
            ensure!(
                crate::freemkv::renesas::hook::abi::memory_call(
                    image,
                    base,
                    write.main_address,
                    0x93,
                    true
                )? == controller_helper,
                "read/write controller helpers differ"
            );
            ensure!(
                crate::freemkv::renesas::hook::abi::memory_call(
                    image,
                    base,
                    write.main_address,
                    0xb0,
                    true
                )? == crate::freemkv::renesas::hook::abi::memory_call(
                    image, base, main, 0xb0, false
                )?,
                "read/write CPU helpers differ"
            );
            Ok(())
        }
    }

    pub(super) mod operations {
        //! Firmware-bound activation and runtime protocol.
        use crate::freemkv::renesas::hook::{
            Guard, Relocation, Trampoline,
            firmware::{
                Ea, Insn, Operand, Reg, Size, abs, cdb_byte, compare_byte, emit, emit_op,
                instruction, pop, push,
            },
        };
        use anyhow::{Context, Result, ensure};
        use h8_asm::{Asm, Mode, Target};

        fn unique_signature(image: &[u8], pattern: &[(u16, u16)]) -> Result<usize> {
            unique_signatures(image, &[pattern])
        }

        fn unique_signatures(image: &[u8], patterns: &[&[(u16, u16)]]) -> Result<usize> {
            use h8_asm::image::{Needle, find};
            let mut found = None;
            for pattern in patterns {
                let needle = Needle::Masked(pattern);
                if let Some(at) = find(image, needle, 0) {
                    ensure!(
                        found.is_none() && find(image, needle, at + 2).is_none(),
                        "ambiguous firmware signature"
                    );
                    found = Some(at);
                }
            }
            found.context("missing firmware signature")
        }

        /// Addresses read and written by the complete cached eligibility getter.
        fn eligibility_getter(image: &[u8]) -> Result<usize> {
            unique_signature(
                image,
                &[
                    (0x0100, 0xffff),
                    (0x6df3, 0xffff),
                    (0x6a28, 0xffff),
                    (0x0000, 0x0000),
                    (0x0000, 0x0000),
                    (0x4634, 0xffff),
                    (0x0100, 0xffff),
                    (0x6b23, 0xffff),
                    (0x0000, 0x0000),
                    (0x0000, 0x0000),
                    (0x0100, 0xffff),
                    (0x6930, 0xffff),
                    (0x0100, 0xffff),
                    (0x6f02, 0xffff),
                    (0x0100, 0xffff),
                    (0x0100, 0xffff),
                    (0x6f00, 0xffff),
                    (0x00fa, 0xffff),
                    (0x0ab0, 0xffff),
                    (0x5d20, 0xffff),
                    (0x0c88, 0xffff),
                    (0x4704, 0xffff),
                    (0xf801, 0xffff),
                    (0x4002, 0xffff),
                    (0x1888, 0xffff),
                    (0x6aa8, 0xffff),
                    (0x0000, 0x0000),
                    (0x0000, 0x0000),
                    (0xf801, 0xffff),
                    (0x6aa8, 0xffff),
                    (0x0000, 0x0000),
                    (0x0000, 0x0000),
                    (0x6a28, 0xffff),
                    (0x0000, 0x0000),
                    (0x0000, 0x0000),
                    (0x0100, 0xffff),
                    (0x6d73, 0xffff),
                    (0x5470, 0xffff),
                ],
            )
            .context("eligibility getter")
        }

        fn eligibility_state(image: &[u8]) -> Result<(u32, u32, u32)> {
            use h8_asm::image::read_u32;
            let at = eligibility_getter(image)?;
            h8_asm::analysis::reachable(image, at.try_into()?, Target::H8S2000, Mode::Advanced)
                .map_err(|e| anyhow::anyhow!("eligibility getter control flow: {e:?}"))?;
            let checked = read_u32(image, at + 6).context("missing checked address")?;
            let object = read_u32(image, at + 16).context("missing security object address")?;
            let result = read_u32(image, at + 52).context("missing result address")?;
            ensure!(
                read_u32(image, at + 60) == Some(checked)
                    && read_u32(image, at + 66) == Some(result),
                "inconsistent eligibility cache addresses"
            );
            ensure!(
                checked != result
                    && checked > 0
                    && result > 0
                    && checked < 0x1000000
                    && result < 0x1000000
                    && object > 0
                    && object < 0x1000000
                    && object % 2 == 0,
                "invalid eligibility state addresses"
            );
            Ok((checked, result, object))
        }

        // OEM delay adapter: unsigned duration, kernel call, status assertion 0x16.
        // Call the kernel directly so failure is returned instead of entering diagnostics.
        fn scheduler_delay(image: &[u8]) -> Result<u32> {
            let at = unique_signature(
                image,
                &[
                    (0x1770, 0xffff),
                    (0x5e00, 0xff00),
                    (0, 0),
                    (0x0d08, 0xffff),
                    (0x1911, 0xffff),
                    (0x0d00, 0xffff),
                    (0x4602, 0xffff),
                    (0xf901, 0xffff),
                    (0x0d10, 0xffff),
                    (0xf016, 0xffff),
                    (0x1899, 0xffff),
                    (0x5e00, 0xff00),
                    (0, 0),
                    (0x5470, 0xffff),
                ],
            )
            .context("OEM scheduler delay adapter")?;
            let target = h8_asm::image::read_u32(image, at + 2).context("delay target")? & 0xffffff;
            ensure!(
                (0x400000..0x410000).contains(&target) && target.is_multiple_of(2),
                "delay target outside kernel"
            );
            Ok(target)
        }

        fn read_engine_state(image: &[u8]) -> Result<u32> {
            let at = unique_signature(
                image,
                &[
                    (0x6a08, 0xffff),
                    (0, 0),
                    (0xa808, 0xffff),
                    (0x4408, 0xffff),
                    (0x0c88, 0xffff),
                    (0x4704, 0xffff),
                    (0xf801, 0xffff),
                    (0x4002, 0xffff),
                    (0x1888, 0xffff),
                    (0x5470, 0xffff),
                ],
            )
            .context("OEM read-engine busy predicate")?;
            let state =
                h8_asm::image::read_u16(image, at + 2).context("missing read-engine state")? as u32;
            ensure!(
                (1..0x8000).contains(&state),
                "unsupported read-engine state address"
            );
            Ok(state)
        }

        fn activation_buffers(image: &[u8]) -> Result<[u32; 2]> {
            use h8_asm::image::{read_u16, read_u32};
            let at = unique_signature(
                image,
                &[
                    (0x1933, 0xffff),
                    (0x0d31, 0xffff),
                    (0x1771, 0xffff),
                    (0x6e1c, 0xffff),
                    (0, 0),
                    (0x7810, 0xffff),
                    (0x6aac, 0xffff),
                    (0, 0),
                    (0, 0),
                    (0x0b53, 0xffff),
                    (0x7923, 0xffff),
                    (0x0010, 0xffff),
                    (0x45e8, 0xffff),
                ],
            )
            .context("acquisition buffer copy")?;
            let source = read_u16(image, at + 8).context("missing acquisition source")? as u32;
            let destination =
                read_u32(image, at + 14).context("missing acquisition destination")?;
            ensure!(
                (2..=0x7ff0).contains(&source)
                    && (0xa00000..=0xdffff0).contains(&destination)
                    && source.is_multiple_of(2)
                    && destination.is_multiple_of(2),
                "invalid acquisition buffers"
            );
            Ok([source, destination])
        }

        fn verify_buffer_owner(
            image: &[u8],
            base: u32,
            dispatcher: u32,
            acquisition: &Guard,
            buffers: [u32; 2],
        ) -> Result<()> {
            use h8_asm::image::{Needle, find, read_u32};
            // This consumer copies the output only after dispatching 13A.
            let mut consumer = vec![
                0x79, 0x01, 0x01, 0x3a, 0x69, 0xf1, 0x18, 0x99, 0x6e, 0xf9, 0x00, 0x02, 0x0f, 0xf1,
                0x1a, 0xa2,
            ];
            consumer.extend(abs(0x5e, dispatcher)?);
            consumer.extend([
                0x6e, 0xf8, 0x00, 0x2c, 0xa8, 0x01, 0x58, 0x70, 0x00, 0xcc, 0x19, 0x33, 0x0d, 0x31,
                0x17, 0x71, 0x6e, 0x1c,
            ]);
            consumer.extend(u16::try_from(buffers[0])?.to_be_bytes());
            consumer.extend([0x78, 0x10, 0x6a, 0xac]);
            consumer.extend(buffers[1].to_be_bytes());
            let consumer_at = find(image, Needle::Bytes(&consumer), 0)
                .context("acquisition copy is not linked to the 13A dispatcher")?;
            ensure!(
                find(image, Needle::Bytes(&consumer), consumer_at + 1).is_none(),
                "ambiguous acquisition buffer consumer"
            );

            let table = read_u32(&acquisition.expected, 0).context("missing acquisition table")?;
            let table_offset = table
                .checked_sub(base)
                .context("acquisition table outside image")?
                as usize;
            let main =
                read_u32(image, table_offset + 16).context("missing acquisition callback")?;
            let mut mapped = vec![0; base as usize];
            mapped.extend_from_slice(image);
            let reachable =
                h8_asm::analysis::reachable(&mapped, main, Target::H8S2000, Mode::Advanced)
                    .map_err(|e| anyhow::anyhow!("acquisition buffer ownership: {e:?}"))?;
            let mut output = vec![0x7a, 0x02]; // MOV.L #buffer,ER2; clear R1L; JSR @ER3.
            output.extend(buffers[0].to_be_bytes());
            output.extend([0x18, 0x99, 0x5d, 0x30]);
            ensure!(
                reachable.iter().any(|&at| {
                    let at = at as usize;
                    mapped.get(at..at + output.len()) == Some(output.as_slice())
                }),
                "13A does not populate the discovered acquisition buffer"
            );
            Ok(())
        }

        fn cache_reset(image: &[u8]) -> Result<usize> {
            unique_signature(
                image,
                &[
                    (0x1888, 0xffff),
                    (0x6aa8, 0xffff),
                    (0, 0),
                    (0, 0),
                    (0x6aa8, 0xffff),
                    (0, 0),
                    (0, 0),
                    (0x6aa8, 0xffff),
                    (0, 0),
                    (0, 0),
                    (0x6aa8, 0xffff),
                    (0, 0),
                    (0, 0),
                    (0x6aa8, 0xffff),
                    (0, 0),
                    (0, 0),
                    (0x5470, 0xffff),
                    (0x6a28, 0xffff),
                    (0, 0),
                    (0, 0),
                    (0x5470, 0xffff),
                ],
            )
            .context("security cache reset and loaded getter")
        }

        fn loaded_state(image: &[u8], checked: u32, result: u32) -> Result<u32> {
            use h8_asm::image::read_u32;
            let at = cache_reset(image)?;
            let loaded = read_u32(image, at + 10).context("missing loaded flag")?;
            ensure!(
                read_u32(image, at + 22) == Some(checked)
                    && read_u32(image, at + 28) == Some(result)
                    && read_u32(image, at + 36) == Some(loaded),
                "inconsistent security state references"
            );
            ensure!(
                loaded > 0 && loaded < 0x1000000 && loaded != checked && loaded != result,
                "invalid loaded flag"
            );
            Ok(loaded)
        }

        fn internal_dispatcher(image: &[u8], base: u32) -> Result<u32> {
            let at = unique_signature(
                image,
                &[
                    (0x0100, 0xffff),
                    (0x6df3, 0xffff),
                    (0x0120, 0xffff),
                    (0x6df4, 0xffff),
                    (0x7937, 0xffff),
                    (0x0020, 0xffff),
                    (0x0100, 0xffff),
                    (0x6ff2, 0xffff),
                    (0x001c, 0xffff),
                    (0x0100, 0xffff),
                    (0x6ff1, 0xffff),
                    (0x0016, 0xffff),
                    (0xfd01, 0xffff),
                    (0x6910, 0xffff),
                    (0x5e00, 0xff00),
                    (0x0000, 0x0000),
                    (0x0f86, 0xffff),
                    (0x0100, 0xffff),
                    (0x6901, 0xffff),
                    (0x0100, 0xffff),
                    (0x6910, 0xffff),
                    (0x0100, 0xffff),
                    (0x6f03, 0xffff),
                    (0x0010, 0xffff),
                ],
            )
            .context("internal dispatcher")?;
            let refs = h8_asm::analysis::xrefs(image, at..at + 48, Target::H8S2000, Mode::Advanced)
                .map_err(|e| anyhow::anyhow!("internal dispatcher instructions: {e:?}"))?;
            ensure!(
                refs.len() == 1 && refs[0].kind == h8_asm::analysis::XrefKind::Call,
                "unexpected dispatcher control flow"
            );
            ensure!(
                refs[0].to == Some(operation_lookup(image, base)?.0),
                "dispatcher uses a different operation lookup"
            );
            let lookup = refs[0]
                .to
                .and_then(|address| address.checked_sub(base))
                .context("dispatcher lookup outside image")? as usize;
            let prefix = [
                0x17, 0xf0, 0x0f, 0x81, 0x10, 0x30, 0x0a, 0x90, 0x10, 0x30, 0x7a, 0x10,
            ];
            ensure!(
                image.get(lookup..lookup + prefix.len()) == Some(prefix.as_slice()),
                "dispatcher does not call the operation lookup"
            );
            verify_dispatcher_returns(image, base, at)?;
            base.checked_add(at.try_into()?)
                .context("dispatcher address overflow")
        }

        fn verify_dispatcher_returns(image: &[u8], base: u32, entry: usize) -> Result<()> {
            // The hook relies on the dispatcher's saved-register and stack ABI.
            // Validate each reachable return, not merely its entry signature.
            const EPILOGUE: &[u8] = &[
                0x0c, 0xd8, 0x79, 0x17, 0x00, 0x20, 0x01, 0x20, 0x6d, 0x76, 0x01, 0x00, 0x6d, 0x73,
                0x54, 0x70,
            ];
            let mut mapped = vec![0; base as usize];
            mapped.extend_from_slice(image);
            let reachable = h8_asm::analysis::reachable(
                &mapped,
                base + u32::try_from(entry)?,
                Target::H8S2000,
                Mode::Advanced,
            )
            .map_err(|e| anyhow::anyhow!("dispatcher return flow: {e:?}"))?;
            let mut returns = 0;
            let mut cut = mapped.clone();
            for &address in &reachable {
                let end = address as usize;
                if mapped.get(end..end + 2) != Some(&[0x54, 0x70]) {
                    continue;
                }
                returns += 1;
                let start = end
                    .checked_sub(14)
                    .context("truncated dispatcher epilogue")?;
                ensure!(
                    mapped.get(start..end + 2) == Some(EPILOGUE),
                    "unsupported dispatcher return ABI"
                );
                cut[start..start + 2].copy_from_slice(&[0x54, 0x70]);
                for offset in [0, 2, 6, 10] {
                    ensure!(
                        reachable.binary_search(&((start + offset) as u32)).is_ok(),
                        "dispatcher bypasses register restoration"
                    );
                }
            }
            ensure!(returns > 0, "dispatcher has no return");
            let bypass = h8_asm::analysis::reachable(
                &cut,
                base + u32::try_from(entry)?,
                Target::H8S2000,
                Mode::Advanced,
            )
            .map_err(|e| anyhow::anyhow!("dispatcher epilogue bypass: {e:?}"))?;
            ensure!(
                !bypass
                    .iter()
                    .any(|&at| { mapped.get(at as usize..at as usize + 2) == Some(&[0x54, 0x70]) }),
                "dispatcher can bypass its restoration epilogue"
            );
            Ok(())
        }

        fn security_layout(image: &[u8], base: u32, object: u32) -> Result<(u32, u32, usize)> {
            use h8_asm::image::{Needle, find, read_u32};
            let assignment = unique_signature(
                image,
                &[
                    (0x5e00, 0xff00),
                    (0, 0),
                    (0x0100, 0xffff),
                    (0x6ba0, 0xffff),
                    ((object >> 16) as u16, 0xffff),
                    (object as u16, 0xffff),
                ],
            )
            .context("eligibility object assignment")?;
            let accessor = (read_u32(image, assignment).context("object accessor call")? & 0xffffff)
                .checked_sub(base)
                .context("object accessor outside firmware")? as usize;
            let accessor_pattern = [
                (0x7a00, 0xffff),
                (0, 0),
                (0, 0),
                (0x5e00, 0xff00),
                (0, 0),
                (0x7a00, 0xffff),
                (0, 0),
                (0, 0),
                (0x5470, 0xffff),
            ];
            ensure!(
                find(image, Needle::Masked(&accessor_pattern), accessor) == Some(accessor),
                "unsupported object accessor"
            );
            let object_slot = read_u32(image, accessor + 12).context("missing object slot")?;
            let constructor = unique_signature(
                image,
                &[
                    (0x7a00, 0xfff8),
                    (0, 0),
                    (0, 0),
                    (0x0100, 0xffff),
                    (0x6ba0, 0xfff8),
                    ((object_slot >> 16) as u16, 0xffff),
                    (object_slot as u16, 0xffff),
                ],
            )
            .context("security object constructor")?;
            ensure!(
                image[constructor + 1] & 7 == image[constructor + 9] & 7,
                "security constructor register mismatch"
            );
            let table = read_u32(image, constructor + 2)
                .context("security table address")?
                .checked_sub(base)
                .context("security table outside firmware")? as usize;
            let address = read_u32(image, table + 0x100).context("missing eligibility method")?;
            let root = address
                .checked_sub(base)
                .context("eligibility method outside firmware")? as usize;
            let a_check = [
                (0x6df3, 0xffff),
                (0x18bb, 0xffff),
                (0xf802, 0xffff),
                (0x5e00, 0xff00),
                (0, 0),
                (0x5e00, 0xff00),
                (0, 0),
                (0xa821, 0xffff),
            ];
            ensure!(
                find(image, Needle::Masked(&a_check), root) == Some(root),
                "missing record-A eligibility anchor"
            );
            h8_asm::analysis::reachable(image, root.try_into()?, Target::H8S2000, Mode::Advanced)
                .map_err(|e| anyhow::anyhow!("record eligibility control flow: {e:?}"))?;
            ensure!(
                image
                    .get(table..table + 16)
                    .is_some_and(|b| b.iter().all(|v| *v == 0)),
                "unrecognized security table header"
            );
            // Null methods can occur inside the table. Its boundary must also
            // be the start of a table referenced by an OEM constructor.
            let mut length = None;
            for method in 0..256 {
                let end = table + 16 + method * 10;
                let callback = read_u32(image, end).context("truncated security method")?;
                ensure!(
                    callback == 0
                        || (callback % 2 == 0
                            && callback
                                .checked_sub(base)
                                .is_some_and(|off| (off as usize) < image.len())),
                    "invalid security method"
                );
                ensure!(
                    image
                        .get(end - 6..end)
                        .is_some_and(|b| b.iter().all(|v| *v == 0)),
                    "unsupported security method adjustment"
                );
                let next = end + 4;
                if method < 24
                    || !image
                        .get(next..next + 16)
                        .is_some_and(|b| b.iter().all(|v| *v == 0))
                {
                    continue;
                }
                let next_address = base
                    .checked_add(next.try_into()?)
                    .context("table boundary overflow")?;
                let mut referenced = false;
                for reg in 0..=6u16 {
                    let constructor = [
                        (0x7a00 | reg, 0xffff),
                        ((next_address >> 16) as u16, 0xffff),
                        (next_address as u16, 0xffff),
                        (0x0100, 0xffff),
                        (0x6980 | reg, 0xff8f),
                    ];
                    referenced |= find(image, Needle::Masked(&constructor), 0).is_some();
                }
                if referenced {
                    length = Some(next - table);
                    break;
                }
            }
            let length = length.context("missing security table boundary constructor")?;
            let table_address = base
                .checked_add(table.try_into()?)
                .context("security table address overflow")?;
            let mut slot = None;
            for reg in 0..=6u16 {
                let signature = [
                    (0x7a00 | reg, 0xffff),
                    ((table_address >> 16) as u16, 0xffff),
                    (table_address as u16, 0xffff),
                    (0x0100, 0xffff),
                    (0x6ba0 | reg, 0xffff),
                    (0, 0),
                    (0, 0),
                ];
                let mut start = 0;
                while let Some(at) = find(image, Needle::Masked(&signature), start) {
                    start = at + 2;
                    ensure!(slot.is_none(), "ambiguous security initializer");
                    slot = read_u32(image, at + 10);
                }
            }
            let slot = slot.context("missing security initializer")?;
            ensure!(
                super::writable_ram(slot, 4) && slot % 2 == 0,
                "invalid security object slot"
            );
            Ok((slot, table_address, length))
        }

        fn verify_security_object(image: &[u8], base: u32, slot: u32, object: u32) -> Result<()> {
            let stub = unique_signature(
                image,
                &[
                    (0x7a00, 0xffff),
                    (0, 0),
                    (0, 0),
                    (0x5e00, 0xff00),
                    (0, 0),
                    (0x7a00, 0xffff),
                    ((slot >> 16) as u16, 0xffff),
                    (slot as u16, 0xffff),
                    (0x5470, 0xffff),
                ],
            )
            .context("security object accessor")?;
            let mut initializer = abs(
                0x5e,
                base.checked_add(stub.try_into()?)
                    .context("accessor address overflow")?,
            )?
            .to_vec();
            initializer.extend([1, 0, 0x6b, 0xa0]);
            initializer.extend(object.to_be_bytes());
            let at = h8_asm::image::find(image, h8_asm::image::Needle::Bytes(&initializer), 0)
                .context("security object is not assigned to eligibility getter")?;
            ensure!(at % 2 == 0, "unaligned security object initializer");
            Ok(())
        }

        /// Discover the internal acquisition callback through its operation-table
        /// lookup, dispatcher use, and matching object initialization.
        fn operation_lookup(image: &[u8], base: u32) -> Result<(u32, u32)> {
            use h8_asm::image::{Needle, find, read_u32};
            let lookup = Needle::Masked(&[
                (0x17f0, 0xffff),
                (0x0f81, 0xffff),
                (0x1030, 0xffff),
                (0x0a90, 0xffff),
                (0x1030, 0xffff),
                (0x7a10, 0xffff),
                (0, 0),
                (0, 0),
                (0x5470, 0xffff),
            ]);
            let at = find(image, lookup, 0).context("missing internal operation lookup")?;
            ensure!(
                find(image, lookup, at + 2).is_none(),
                "ambiguous internal operation lookup"
            );
            let table = read_u32(image, at + 12).context("truncated operation lookup")?;
            Ok((
                base.checked_add(at.try_into()?)
                    .context("lookup address overflow")?,
                table,
            ))
        }

        fn acquisition_guard(image: &[u8], base: u32) -> Result<Guard> {
            operation_guard(image, base, 0x13a, [1, 0])
        }
        fn operation_guard(
            image: &[u8],
            base: u32,
            operation: u32,
            flags: [u8; 2],
        ) -> Result<Guard> {
            use h8_asm::image::{Needle, find, read_u32};
            let (lookup_address, table) = operation_lookup(image, base)?;
            let entry = table
                .checked_sub(base)
                .and_then(|off| off.checked_add(operation * 6))
                .context("internal acquisition table outside image")?
                as usize;
            ensure!(
                image.get(entry + 4..entry + 6) == Some(flags.as_slice()),
                "unsupported internal operation flags"
            );
            let slot = read_u32(image, entry).context("missing internal acquisition entry")?;
            ensure!(
                slot % 2 == 0 && super::writable_ram(slot, 4),
                "invalid acquisition object address"
            );
            let mut caller = vec![0x69, 0x10];
            caller.extend(abs(0x5e, lookup_address)?);
            caller.extend([
                0x0f, 0x86, 1, 0, 0x69, 1, 1, 0, 0x69, 0x10, 1, 0, 0x6f, 3, 0, 0x10,
            ]);
            ensure!(
                find(image, Needle::Bytes(&caller), 0).is_some(),
                "unverified internal dispatcher"
            );
            let mut original = None;
            for register in 0..=6u16 {
                let initializer = [
                    (0x7a00 | register, 0xffff),
                    (0, 0),
                    (0, 0),
                    (0x0100, 0xffff),
                    (0x6ba0 | register, 0xffff),
                    ((slot >> 16) as u16, 0xffff),
                    (slot as u16, 0xffff),
                ];
                let mut start = 0;
                while let Some(at) = find(image, Needle::Masked(&initializer), start) {
                    start = at + 2;
                    let address =
                        read_u32(image, at + 2).context("truncated acquisition initializer")?;
                    let offset = address
                        .checked_sub(base)
                        .context("acquisition table below image")?
                        as usize;
                    // CF disables preparation/cleanup in its dispatch entry;
                    // its optional methods need not be present.
                    let fields: &[usize] = if flags == [0, 0] {
                        &[16]
                    } else {
                        &[16, 26, 36, 46, 56, 66]
                    };
                    for &field in fields {
                        ensure!(
                            image
                                .get(offset + field - 6..offset + field)
                                .is_some_and(|bytes| bytes.iter().all(|b| *b == 0)),
                            "unsupported operation callback adjustment"
                        );
                        let callback = read_u32(image, offset + field)
                            .context("truncated acquisition table")?;
                        ensure!(
                            callback % 2 == 0
                                && callback
                                    .checked_sub(base)
                                    .is_some_and(|off| (off as usize) < image.len()),
                            "invalid acquisition callback"
                        );
                    }
                    ensure!(
                        original.replace(address).is_none(),
                        "ambiguous acquisition initializer"
                    );
                }
            }
            Ok(Guard {
                cpu_address: slot,
                expected: original
                    .context("missing acquisition initializer")?
                    .to_be_bytes()
                    .to_vec(),
            })
        }

        fn verify_cf(image: &[u8], base: u32, dispatcher: u32) -> Result<Guard> {
            use h8_asm::image::read_u32;
            let guard = operation_guard(image, base, 0xcf, [0, 0])?;
            let table = read_u32(&guard.expected, 0).context("missing CF table")?;
            let main =
                read_u32(image, (table - base) as usize + 16).context("missing CF callback")?;
            let tail = unique_signature(
                image,
                &[
                    (0x7901, 0xffff),
                    (0x012b, 0xffff),
                    (0x0f80, 0xff8f),
                    (0x5e00, 0xff00),
                    (0x0000, 0x0000),
                    (0xf858, 0xffff),
                    (0x5e00, 0xff00),
                    (0x0000, 0x0000),
                    (0x5e00, 0xff00),
                    (0x0000, 0x0000),
                    (0x0c88, 0xffff),
                    (0x471a, 0xffff),
                    (0x7901, 0xffff),
                    (0x013d, 0xffff),
                    (0x0f80, 0xff8f),
                    (0x5e00, 0xff00),
                    (0x0000, 0x0000),
                    (0xa801, 0xffff),
                    (0x460c, 0xffff),
                    (0x7a00, 0xffff),
                    (0x0000, 0x0000),
                    (0x0000, 0x0000),
                    (0x5e00, 0xff00),
                    (0x0000, 0x0000),
                    (0x4004, 0xffff),
                    (0x1888, 0xffff),
                    (0x4002, 0xffff),
                    (0xf801, 0xffff),
                    (0x7917, 0xffff),
                    (0x0000, 0x0000),
                    (0x0100, 0xffcf),
                    (0x6d70, 0xfff8),
                    (0x5470, 0xffff),
                ],
            )
            .context("CF eligibility tail")?;
            let frame = h8_asm::image::read_u16(image, tail + 58).context("CF stack frame")?;
            let descriptor = frame
                .checked_sub(20)
                .context("CF descriptor outside frame")?;
            let context = (image[tail + 5] >> 4) & 7;
            let saved = image[tail + 61];
            ensure!(
                image[tail + 29] == image[tail + 5]
                    && image[tail + 63] == 0x74 + (saved >> 4)
                    && (4..=4 + (saved >> 4)).contains(&context),
                "inconsistent CF register preservation"
            );
            let entry = [
                1,
                saved,
                0x6d,
                0xf4,
                0x79,
                0x37,
                (frame >> 8) as u8,
                frame as u8,
                0x0f,
                0x80 | context,
            ];
            let acquisition = unique_signature(
                image,
                &[
                    (0x6ef9, 0xffff),
                    (descriptor + 2, 0xffff),
                    (0x0ff1, 0xffff),
                    (0x7911, 0xffff),
                    (descriptor, 0xffff),
                    (0x0f80 | ((context as u16) << 4), 0xffff),
                    (0x1aa2, 0xffff),
                    (0x5e00 | ((dispatcher >> 16) as u16), 0xffff),
                    (dispatcher as u16, 0xffff),
                    (0xa801, 0xffff),
                    (0x4608, 0xffff),
                    (0x7a00, 0xffff),
                    (0, 0),
                    (0, 0),
                ],
            )
            .context("CF acquisition dispatch")?;
            let start = acquisition
                .checked_sub(16)
                .context("truncated CF descriptor")?;
            let descriptor_pattern = [
                (0x7901, 0xffff),
                (0x013a, 0xffff),
                (0x6ff1, 0xffff),
                (descriptor, 0xffff),
            ];
            let assignment = unique_signature(&image[start..acquisition], &descriptor_pattern)
                .context("CF acquisition descriptor")?
                + start;
            let call = |at: usize| -> Result<u32> {
                Ok(read_u32(image, at).context("truncated CF call")? & 0xffffff)
            };
            ensure!(
                call(tail + 16)? == base + eligibility_getter(image)? as u32,
                "CF uses different eligibility getter"
            );
            ensure!(
                call(tail + 6)? == call(tail + 30)?,
                "CF nested-operation calling conventions differ"
            );
            let mut mapped = vec![0; base as usize];
            mapped.extend_from_slice(image);
            let reachable =
                h8_asm::analysis::reachable(&mapped, main, Target::H8S2000, Mode::Advanced)
                    .map_err(|e| anyhow::anyhow!("CF control flow: {e:?}"))?;
            ensure!(
                reachable.binary_search(&(base + tail as u32)).is_ok(),
                "CF does not reach acquisition path"
            );
            ensure!(
                [assignment, acquisition]
                    .iter()
                    .all(|at| reachable.binary_search(&(base + *at as u32)).is_ok()),
                "CF acquisition evidence is unreachable"
            );
            let mut at = assignment + 8;
            while at < acquisition {
                let decoded =
                    h8_asm::isa::decode_insn(&image[at..], Target::H8S2000, Mode::Advanced)
                        .map_err(|e| anyhow::anyhow!("CF acquisition setup: {e:?}"))?;
                ensure!(
                    matches!(decoded.insn.mnemonic, "MOV" | "SUB" | "BNE"),
                    "unsupported CF acquisition setup"
                );
                ensure!(
                    decoded.insn.operands.iter().all(|operand| match operand {
                        Operand::None | Operand::Immediate { .. } => true,
                        Operand::Register(Reg::Byte(r)) => *r != 7 && *r != 15,
                        Operand::Address(Ea::PcRelative { value, .. }) => {
                            let target = at as i64 + decoded.len as i64 + *value as i64;
                            target > at as i64 && target <= acquisition as i64
                        }
                        _ => false,
                    }),
                    "CF acquisition setup can alter its descriptor or stack"
                );
                at += decoded.len as usize;
            }
            ensure!(at == acquisition, "unaligned CF acquisition setup");
            let main = main as usize;
            ensure!(
                mapped.get(main..main + 10) == Some(entry.as_slice()),
                "unsupported CF entry ABI"
            );
            ensure!(
                mapped.get(main + 10) == Some(&0x5e),
                "CF does not begin with reset"
            );
            let reset = read_u32(&mapped, main + 10).context("missing CF reset")? & 0xffffff;
            let reset_path =
                h8_asm::analysis::reachable(&mapped, reset, Target::H8S2000, Mode::Advanced)
                    .map_err(|e| anyhow::anyhow!("CF reset control flow: {e:?}"))?;
            let clear = abs(0x5e, base + cache_reset(image)? as u32)?;
            ensure!(
                reset_path
                    .iter()
                    .any(|at| mapped.get(*at as usize..*at as usize + 4) == Some(clear.as_slice())),
                "CF reset does not clear the discovered security cache"
            );
            // Cut the analysis graph at every cache-clear call. No original
            // return may remain reachable without crossing one of those calls.
            let mut cut = mapped.clone();
            for &at in &reset_path {
                let at = at as usize;
                if mapped.get(at..at + 4) == Some(clear.as_slice()) {
                    cut[at..at + 2].copy_from_slice(&[0x54, 0x70]);
                }
            }
            let bypass = h8_asm::analysis::reachable(&cut, reset, Target::H8S2000, Mode::Advanced)
                .map_err(|e| anyhow::anyhow!("CF reset bypass analysis: {e:?}"))?;
            ensure!(
                !bypass
                    .iter()
                    .any(|&at| mapped.get(at as usize..at as usize + 2) == Some(&[0x54, 0x70])),
                "CF reset can return without clearing the security cache"
            );
            Ok(guard)
        }

        #[derive(Clone, Debug)]
        pub(super) struct VidSites {
            pub slot: u32,
            pub table: u32,
            pub main: u32,
            pub status: u32,
            pub source: u32,
        }
        fn vid_sites(image: &[u8], base: u32) -> Result<VidSites> {
            let site = super::discovery::opcode_site(image, base, 0xad)?;
            let at = unique_signature(
                image,
                &[
                    (0x6a08, 0xffff),
                    (0, 0),
                    (0x7718, 0xffff),
                    (0x4400, 0xff00),
                    (0x0c99, 0xffff),
                    (0x4600, 0xff00),
                    (0x7a00, 0xffff),
                    (0, 0),
                    (0, 0),
                    (0x5e00, 0xff00),
                    (0, 0),
                    (0x1933, 0xffff),
                    (0x7a06, 0xffff),
                    (0, 0),
                    (0, 0),
                    (0x0d31, 0xffff),
                    (0x1771, 0xffff),
                    (0x0f90, 0xffff),
                    (0x0ae0, 0xffff),
                    (0x680c, 0xffff),
                    (0x0f90, 0xffff),
                    (0x0ad0, 0xffff),
                    (0x688c, 0xffff),
                ],
            )
            .context("hardware VID reader")?;
            let status = h8_asm::image::read_u16(image, at + 2).context("VID status")?;
            let source = h8_asm::image::read_u32(image, at + 26).context("VID source")?;
            ensure!(
                status >= 0xe000 && (0xffffe000..=0xfffffff0).contains(&source),
                "invalid VID register window"
            );
            ensure!(
                super::writable_ram(site.object_address, 4),
                "invalid VID callback slot"
            );
            Ok(VidSites {
                slot: site.object_address,
                table: site.table_address,
                main: site.main_address,
                status: 0xffff0000 | u32::from(status),
                source,
            })
        }

        #[derive(Clone, Debug)]
        pub(super) struct Sites {
            pub vid: VidSites,
            pub read_engine_state: u32,
            pub scheduler_delay: u32,
            pub acquisition: Guard,
            pub reset: Guard,
            pub loaded: u32,
            pub checked: u32,
            pub result: u32,
            pub security_slot: u32,
            pub security_table: u32,
            pub table_length: usize,
            pub dispatcher: u32,
            pub buffers: [u32; 2],
        }
        impl Sites {
            fn discover(image: &[u8], base: u32) -> Result<Self> {
                let (checked, result, object) = eligibility_state(image)?;
                let loaded = loaded_state(image, checked, result)?;
                let (security_slot, security_table, table_length) =
                    security_layout(image, base, object)?;
                verify_security_object(image, base, security_slot, object)?;
                ensure!(
                    checked < 0x8000 && result < 0x8000,
                    "unsupported cache address width"
                );
                let dispatcher = internal_dispatcher(image, base)?;
                let reset = verify_cf(image, base, dispatcher)?;
                let acquisition = acquisition_guard(image, base)?;
                let buffers = activation_buffers(image)?;
                verify_buffer_owner(image, base, dispatcher, &acquisition, buffers)?;
                Ok(Self {
                    vid: vid_sites(image, base)?,
                    read_engine_state: read_engine_state(image)?,
                    scheduler_delay: scheduler_delay(image)?,
                    acquisition,
                    reset,
                    loaded,
                    checked,
                    result,
                    security_slot,
                    security_table,
                    table_length,
                    dispatcher,
                    buffers,
                })
            }
            pub(super) fn policy_table(&self, base: u32, payload_len: usize) -> u32 {
                base + (payload_len - self.table_length) as u32
            }
            #[cfg(test)]
            pub(super) fn fixture() -> Self {
                Self {
                    vid: VidSites {
                        slot: 0xe28,
                        table: 0x5b7700,
                        main: 0x446b04,
                        status: 0xffffed3c,
                        source: 0xffffed20,
                    },
                    read_engine_state: 0x2c46,
                    scheduler_delay: 0x40ef76,
                    acquisition: Guard {
                        cpu_address: 0xa0a966,
                        expected: 0x5bf4acu32.to_be_bytes().to_vec(),
                    },
                    reset: Guard {
                        cpu_address: 0xa0b6c8,
                        expected: 0x5cf000u32.to_be_bytes().to_vec(),
                    },
                    loaded: 0x2f86,
                    checked: 0x2f87,
                    result: 0x2f88,
                    security_slot: 0x13b6,
                    security_table: 0x5b8fe4,
                    table_length: 860,
                    dispatcher: 0x5555a6,
                    buffers: [0x2a10, 0xa027f4],
                }
            }
        }
        #[cfg(test)]
        pub(super) const SECURITY_SLOT: u32 = 0x13b6;
        #[cfg(test)]
        pub(super) const SECURITY_TABLE: u32 = 0x5b8fe4;
        #[cfg(test)]
        pub(super) fn policy_table(base: u32, payload_len: usize) -> u32 {
            Sites::fixture().policy_table(base, payload_len)
        }
        #[derive(Clone, Copy)]
        pub(crate) enum Operation {
            Suppress,
        }
        impl Operation {
            pub(crate) fn cdb(self) -> [u8; 10] {
                crate::protocol::build_set_cdb(
                    crate::protocol::Feature::Encryption,
                    crate::protocol::STATE_OFF,
                )
            }
            pub(crate) fn length(self) -> usize {
                64
            }
            #[cfg(test)]
            pub(crate) fn guard(self) -> Guard {
                Sites::fixture().acquisition
            }
        }

        fn label(a: &mut Asm, s: &str) -> Result<()> {
            a.label(s).map_err(|e| anyhow::anyhow!("{e:?}"))
        }
        fn branch(a: &mut Asm, c: u8, s: &str) -> Result<()> {
            a.branch(c, s).map_err(|e| anyhow::anyhow!("{e:?}"))
        }
        fn imm(a: &mut Asm, r: u8, value: u32) -> Result<()> {
            ensure!(
                r < 8 || (0x20..0x28).contains(&r),
                "invalid immediate operation"
            );
            instruction(
                a,
                Insn::new(
                    if r < 8 { "MOV" } else { "CMP" },
                    Some(Size::Long),
                    [
                        Operand::Immediate { value, bits: 32 },
                        Operand::Register(Reg::Long(r & 7)),
                        Operand::None,
                    ],
                ),
            )
        }
        fn store_long(a: &mut Asm, r: u8, at: u32) -> Result<()> {
            instruction(
                a,
                Insn::new(
                    "MOV",
                    Some(Size::Long),
                    [
                        Operand::Register(Reg::Long(r)),
                        Operand::Address(Ea::Absolute {
                            value: at,
                            bits: 32,
                        }),
                        Operand::None,
                    ],
                ),
            )
        }
        fn load_long(a: &mut Asm, r: u8, at: u32) -> Result<()> {
            instruction(
                a,
                Insn::new(
                    "MOV",
                    Some(Size::Long),
                    [
                        Operand::Address(Ea::Absolute {
                            value: at,
                            bits: 32,
                        }),
                        Operand::Register(Reg::Long(r)),
                        Operand::None,
                    ],
                ),
            )
        }
        fn restore_registers(a: &mut Asm) -> Result<()> {
            for r in (0..=6).rev() {
                pop(a, r)?;
            }
            Ok(())
        }
        fn vid_wrapper(sites: &Sites, helper: u32, invalid: u32) -> Result<Vec<u8>> {
            let mut a =
                Asm::new(Target::H8S2000, Mode::Advanced).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            push(&mut a, 2)?;
            for (offset, value) in [(0, 0xad), (1, 1), (7, 0x80)] {
                cdb_byte(&mut a, offset)?;
                compare_byte(&mut a, value)?;
                branch(&mut a, 6, "vid_oem")?;
            }
            load_long(&mut a, 2, sites.security_slot)?;
            imm(&mut a, 0x22, 0x00999990)?;
            branch(&mut a, 6, "vid_oem")?;
            cdb_byte(&mut a, 10)?;
            emit_op(
                &mut a,
                "AND",
                Some(Size::Byte),
                Operand::Immediate {
                    value: 0x3f,
                    bits: 8,
                },
                Operand::Register(Reg::Byte(10)),
            )?;
            branch(&mut a, 6, "vid_invalid")?;
            cdb_byte(&mut a, 10)?;
            compare_byte(&mut a, 0)?;
            branch(&mut a, 6, "vid_oem")?;
            for offset in [2, 3, 4, 5, 6, 11] {
                cdb_byte(&mut a, offset)?;
                compare_byte(&mut a, 0)?;
                branch(&mut a, 6, "vid_invalid")?;
            }
            push(&mut a, 3)?;
            push(&mut a, 4)?;
            emit_op(
                &mut a,
                "MOV",
                Some(Size::Word),
                Operand::Address(Ea::Displacement {
                    base: Reg::Long(1),
                    value: 8,
                    bits: 16,
                }),
                Operand::Register(Reg::Word(3)),
            )?;
            emit_op(
                &mut a,
                "EXTU",
                Some(Size::Long),
                Operand::Register(Reg::Long(3)),
                Operand::None,
            )?;
            imm(&mut a, 0x23, 0)?;
            branch(&mut a, 7, "vid_empty")?;
            imm(&mut a, 0x23, 36)?;
            branch(&mut a, 5, "vid_length")?;
            imm(&mut a, 3, 36)?;
            label(&mut a, "vid_length")?;
            emit_op(
                &mut a,
                "MOV",
                Some(Size::Byte),
                Operand::Address(Ea::Absolute {
                    value: sites.vid.status,
                    bits: 32,
                }),
                Operand::Register(Reg::Byte(10)),
            )?;
            emit_op(
                &mut a,
                "AND",
                Some(Size::Byte),
                Operand::Immediate { value: 2, bits: 8 },
                Operand::Register(Reg::Byte(10)),
            )?;
            branch(&mut a, 7, "vid_unavailable")?;
            imm(&mut a, 4, 0x00888880)?;
            for offset in 0..16 {
                emit_op(
                    &mut a,
                    "MOV",
                    Some(Size::Byte),
                    Operand::Address(Ea::Absolute {
                        value: sites.vid.source + offset,
                        bits: 32,
                    }),
                    Operand::Register(Reg::Byte(10)),
                )?;
                emit_op(
                    &mut a,
                    "MOV",
                    Some(Size::Byte),
                    Operand::Register(Reg::Byte(10)),
                    Operand::Address(Ea::Displacement {
                        base: Reg::Long(4),
                        value: offset as i32 + 4,
                        bits: 16,
                    }),
                )?;
            }
            emit_op(
                &mut a,
                "MOV",
                Some(Size::Long),
                Operand::Register(Reg::Long(4)),
                Operand::Register(Reg::Long(2)),
            )?;
            emit_op(
                &mut a,
                "SUB",
                Some(Size::Long),
                Operand::Immediate {
                    value: 0xa00000,
                    bits: 32,
                },
                Operand::Register(Reg::Long(2)),
            )?;
            push(&mut a, 3)?;
            emit_op(
                &mut a,
                "SUB",
                Some(Size::Byte),
                Operand::Register(Reg::Byte(9)),
                Operand::Register(Reg::Byte(9)),
            )?;
            emit(&mut a, &abs(0x5e, helper)?)?;
            emit_op(
                &mut a,
                "ADDS",
                Some(Size::Long),
                Operand::Immediate { value: 4, bits: 0 },
                Operand::Register(Reg::Long(7)),
            )?;
            // The transfer helper completes before return. Keep resident bytes immutable.
            emit_op(
                &mut a,
                "SUB",
                Some(Size::Byte),
                Operand::Register(Reg::Byte(10)),
                Operand::Register(Reg::Byte(10)),
            )?;
            for offset in 4..20 {
                emit_op(
                    &mut a,
                    "MOV",
                    Some(Size::Byte),
                    Operand::Register(Reg::Byte(10)),
                    Operand::Address(Ea::Displacement {
                        base: Reg::Long(4),
                        value: offset,
                        bits: 16,
                    }),
                )?;
            }
            branch(&mut a, 0, "vid_return")?;
            label(&mut a, "vid_empty")?;
            emit_op(
                &mut a,
                "SUB",
                Some(Size::Byte),
                Operand::Register(Reg::Byte(8)),
                Operand::Register(Reg::Byte(8)),
            )?;
            label(&mut a, "vid_return")?;
            pop(&mut a, 4)?;
            pop(&mut a, 3)?;
            pop(&mut a, 2)?;
            emit_op(&mut a, "RTS", None, Operand::None, Operand::None)?;
            label(&mut a, "vid_unavailable")?;
            pop(&mut a, 4)?;
            pop(&mut a, 3)?;
            label(&mut a, "vid_invalid")?;
            pop(&mut a, 2)?;
            emit(&mut a, &abs(0x5e, invalid)?)?;
            emit_op(
                &mut a,
                "MOV",
                Some(Size::Byte),
                Operand::Immediate { value: 1, bits: 8 },
                Operand::Register(Reg::Byte(8)),
            )?;
            emit_op(&mut a, "RTS", None, Operand::None, Operand::None)?;
            label(&mut a, "vid_oem")?;
            pop(&mut a, 2)?;
            emit(&mut a, &abs(0x5a, sites.vid.main)?)?;
            a.finish(0).map_err(|e| anyhow::anyhow!("{e:?}"))
        }
        pub(super) fn build(image: &[u8], op: Operation) -> Result<(Trampoline, Sites)> {
            let base = crate::freemkv::renesas::hook::layout::inspect(image)?
                .image_base
                .context("missing firmware base")?;
            let sites = Sites::discover(image, base)?;
            let (main, helper, invalid) = crate::freemkv::renesas::hook::firmware::targets(image)?;
            crate::freemkv::renesas::hook::firmware::write_paths(image, main, helper)?;
            let table = (sites.security_table - base) as usize;
            let bytes = image
                .get(table..table + sites.table_length)
                .context("security table outside image")?;
            let payload = assemble(
                main,
                helper,
                invalid,
                &sites,
                op,
                crate::freemkv::renesas::hook::sha256(image),
                bytes,
            )?;
            Ok((payload, sites))
        }
        fn assemble(
            main: u32,
            helper: u32,
            invalid: u32,
            sites: &Sites,
            op: Operation,
            hash: String,
            security_table: &[u8],
        ) -> Result<Trampoline> {
            let mut a =
                Asm::new(Target::H8S2000, Mode::Advanced).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            crate::freemkv::renesas::hook::routing::enter(&mut a)?;
            if matches!(op, Operation::Suppress) {
                cdb_byte(&mut a, crate::protocol::CDB_VERB)?;
                compare_byte(&mut a, crate::protocol::Verb::Identity as u8)?;
                branch(&mut a, 7, "identity")?;
            }
            for (off, value) in op.cdb().iter().enumerate().skip(4) {
                if matches!(op, Operation::Suppress) && matches!(off, 5 | 6) {
                    continue; // Validate feature/state after framing, before any writes.
                }
                cdb_byte(&mut a, off)?;
                compare_byte(&mut a, *value)?;
                branch(&mut a, 6, "invalid")?;
            }
            if matches!(op, Operation::Suppress) {
                cdb_byte(&mut a, crate::protocol::CDB_FEATURE)?;
                for feature in [
                    crate::protocol::Feature::Speed,
                    crate::protocol::Feature::Region,
                    crate::protocol::Feature::Unrestricted,
                    crate::protocol::Feature::Hrl,
                ] {
                    compare_byte(&mut a, feature as u8)?;
                    branch(&mut a, 7, "acknowledge")?;
                }
                compare_byte(&mut a, crate::protocol::Feature::Encryption as u8)?;
                branch(&mut a, 6, "invalid")?;
                cdb_byte(&mut a, 6)?;
                compare_byte(&mut a, crate::protocol::STATE_ON)?;
                branch(&mut a, 7, "transition")?;
                compare_byte(&mut a, crate::protocol::STATE_PASSTHROUGH)?;
                branch(&mut a, 7, "transition")?;
                compare_byte(&mut a, crate::protocol::STATE_OFF)?;
                branch(&mut a, 6, "invalid")?;
            }
            label(&mut a, "transition")?;
            // Save original OEM arguments and all callee registers before nested calls.
            for r in 0..=6 {
                push(&mut a, r)?;
            }
            // Yield before policy writes: READ may finish before its background worker.
            // 500 x 10 OEM ticks gives five nominal seconds, plus scheduling latency.
            // Callee-preserved ER5/ER6 hold the remaining waits and original CDB pointer.
            emit_op(
                &mut a,
                "MOV",
                Some(Size::Long),
                Operand::Register(Reg::Long(1)),
                Operand::Register(Reg::Long(6)),
            )?;
            imm(&mut a, 5, 500)?;
            label(&mut a, "wait_read_idle")?;
            emit_op(
                &mut a,
                "MOV",
                Some(Size::Byte),
                Operand::Address(Ea::Absolute {
                    value: sites.read_engine_state,
                    bits: 32,
                }),
                Operand::Register(Reg::Byte(10)),
            )?;
            compare_byte(&mut a, 0)?;
            branch(&mut a, 7, "read_idle")?;
            compare_byte(&mut a, 8)?;
            branch(&mut a, 4, "read_idle")?;
            imm(&mut a, 0x25, 0)?;
            branch(&mut a, 7, "refused")?;
            imm(&mut a, 0, 10)?;
            emit(&mut a, &abs(0x5e, sites.scheduler_delay)?)?;
            emit_op(
                &mut a,
                "MOV",
                Some(Size::Word),
                Operand::Register(Reg::Word(0)),
                Operand::Register(Reg::Word(0)),
            )?;
            branch(&mut a, 6, "refused")?;
            emit_op(
                &mut a,
                "SUBS",
                Some(Size::Long),
                Operand::Immediate { value: 1, bits: 0 },
                Operand::Register(Reg::Long(5)),
            )?;
            branch(&mut a, 0, "wait_read_idle")?;
            label(&mut a, "read_idle")?;
            emit_op(
                &mut a,
                "MOV",
                Some(Size::Long),
                Operand::Register(Reg::Long(6)),
                Operand::Register(Reg::Long(1)),
            )?;
            let guard = &sites.acquisition;
            let original = u32::from_be_bytes(guard.expected[..].try_into()?);
            load_long(&mut a, 2, guard.cpu_address)?;
            imm(&mut a, 0x22, original)?;
            branch(&mut a, 6, "refused")?;
            load_long(&mut a, 2, sites.reset.cpu_address)?;
            imm(
                &mut a,
                0x22,
                h8_asm::image::read_u32(&sites.reset.expected, 0).context("missing CF guard")?,
            )?;
            branch(&mut a, 6, "refused")?;
            // Accept only OEM or this exact payload's persistent security table.
            load_long(&mut a, 2, sites.security_slot)?;
            imm(&mut a, 0x22, sites.security_table)?;
            branch(&mut a, 7, "owned_policy")?;
            imm(&mut a, 0x22, 0x00666660)?;
            branch(&mut a, 6, "refused")?;
            label(&mut a, "owned_policy")?;
            cdb_byte(&mut a, 6)?;
            compare_byte(&mut a, crate::protocol::STATE_OFF)?;
            branch(&mut a, 6, "restore_policy")?;
            imm(&mut a, 2, 0x00777770)?;
            store_long(&mut a, 2, sites.security_slot)?;
            imm(&mut a, 2, 0x00111110)?; // temporary acquisition callbacks
            store_long(&mut a, 2, guard.cpu_address)?;
            branch(&mut a, 0, "reinitialize")?;
            label(&mut a, "restore_policy")?;
            imm(&mut a, 2, sites.security_table)?;
            store_long(&mut a, 2, sites.security_slot)?;
            label(&mut a, "reinitialize")?;
            match op {
                Operation::Suppress => {
                    // Match the observed buffer reset: source CPU 0x10, not memset zero.
                    for dest in sites.buffers {
                        for offset in [0, 4, 8, 12] {
                            load_long(&mut a, 2, 0x10 + offset)?;
                            store_long(&mut a, 2, dest + offset)?;
                        }
                    }
                    emit_op(
                        &mut a,
                        "SUBS",
                        Some(Size::Long),
                        Operand::Immediate { value: 4, bits: 0 },
                        Operand::Register(Reg::Long(7)),
                    )?; // local four-byte operation descriptor
                    imm(&mut a, 2, 0x00cf0000)?;
                    emit_op(
                        &mut a,
                        "MOV",
                        Some(Size::Long),
                        Operand::Register(Reg::Long(2)),
                        Operand::Address(Ea::Indirect(Reg::Long(7))),
                    )?;
                    emit_op(
                        &mut a,
                        "MOV",
                        Some(Size::Long),
                        Operand::Register(Reg::Long(7)),
                        Operand::Register(Reg::Long(1)),
                    )?;
                    emit_op(
                        &mut a,
                        "SUB",
                        Some(Size::Long),
                        Operand::Register(Reg::Long(0)),
                        Operand::Register(Reg::Long(0)),
                    )?;
                    emit_op(
                        &mut a,
                        "SUB",
                        Some(Size::Long),
                        Operand::Register(Reg::Long(2)),
                        Operand::Register(Reg::Long(2)),
                    )?;
                    emit(&mut a, &abs(0x5e, sites.dispatcher)?)?;
                    emit_op(
                        &mut a,
                        "ADDS",
                        Some(Size::Long),
                        Operand::Immediate { value: 4, bits: 0 },
                        Operand::Register(Reg::Long(7)),
                    )?;
                }
            }
            // Both OEM success and failure restore the borrowed callback before replying.
            imm(&mut a, 2, original)?;
            store_long(&mut a, 2, guard.cpu_address)?;
            if matches!(op, Operation::Suppress) {
                emit_op(
                    &mut a,
                    "MOV",
                    Some(Size::Byte),
                    Operand::Register(Reg::Byte(8)),
                    Operand::Register(Reg::Byte(8)),
                )?;
                branch(&mut a, 6, "refused")?;
            }
            restore_registers(&mut a)?;
            label(&mut a, "acknowledge")?;
            imm(&mut a, 2, 0x00333330)?;
            label(&mut a, "reply")?;
            push(&mut a, 3)?;
            imm(&mut a, 3, op.length() as u32)?;
            push(&mut a, 3)?;
            emit_op(
                &mut a,
                "SUB",
                Some(Size::Byte),
                Operand::Register(Reg::Byte(9)),
                Operand::Register(Reg::Byte(9)),
            )?;
            emit(&mut a, &abs(0x5e, helper)?)?;
            emit_op(
                &mut a,
                "ADDS",
                Some(Size::Long),
                Operand::Immediate { value: 4, bits: 0 },
                Operand::Register(Reg::Long(7)),
            )?;
            pop(&mut a, 3)?;
            pop(&mut a, 2)?;
            emit_op(&mut a, "RTS", None, Operand::None, Operand::None)?;
            label(&mut a, "refused")?;
            restore_registers(&mut a)?;
            branch(&mut a, 0, "invalid")?;
            if matches!(op, Operation::Suppress) {
                label(&mut a, "identity")?;
                for (off, value) in crate::protocol::build_identity_cdb(64)
                    .iter()
                    .enumerate()
                    .skip(5)
                {
                    cdb_byte(&mut a, off)?;
                    compare_byte(&mut a, *value)?;
                    branch(&mut a, 6, "invalid")?;
                }
                imm(&mut a, 2, 0x00444440)?;
                branch(&mut a, 0, "reply")?;
            }
            label(&mut a, "invalid")?;
            pop(&mut a, 2)?;
            emit(&mut a, &abs(0x5e, invalid)?)?;
            emit_op(
                &mut a,
                "MOV",
                Some(Size::Byte),
                Operand::Immediate { value: 1, bits: 8 },
                Operand::Register(Reg::Byte(8)),
            )?;
            emit_op(&mut a, "RTS", None, Operand::None, Operand::None)?;
            crate::freemkv::renesas::hook::routing::oem(&mut a, main)?;
            let mut bytes = a.finish(0).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            let code_length = bytes.len();
            let callback = bytes.len();
            let mut callback_asm =
                Asm::new(Target::H8S2000, Mode::Advanced).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            match op {
                Operation::Suppress => {
                    emit_op(
                        &mut callback_asm,
                        "MOV",
                        Some(Size::Byte),
                        Operand::Immediate { value: 1, bits: 8 },
                        Operand::Register(Reg::Byte(10)),
                    )?;
                    emit_op(
                        &mut callback_asm,
                        "MOV",
                        Some(Size::Byte),
                        Operand::Register(Reg::Byte(10)),
                        Operand::Address(Ea::Absolute {
                            value: sites.checked,
                            bits: 16,
                        }),
                    )?;
                    emit_op(
                        &mut callback_asm,
                        "SUB",
                        Some(Size::Byte),
                        Operand::Register(Reg::Byte(10)),
                        Operand::Register(Reg::Byte(10)),
                    )?;
                    emit_op(
                        &mut callback_asm,
                        "MOV",
                        Some(Size::Byte),
                        Operand::Register(Reg::Byte(10)),
                        Operand::Address(Ea::Absolute {
                            value: sites.result,
                            bits: 16,
                        }),
                    )?;
                    emit_op(
                        &mut callback_asm,
                        "SUB",
                        Some(Size::Long),
                        Operand::Register(Reg::Long(0)),
                        Operand::Register(Reg::Long(0)),
                    )?;
                    emit_op(&mut callback_asm, "RTS", None, Operand::None, Operand::None)?;
                }
            }
            bytes.extend(
                callback_asm
                    .finish(0)
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?,
            );
            let table_offset = bytes.len() as u32;
            bytes.resize(bytes.len() + 40, 0);
            let temp = bytes.len();
            bytes.resize(temp + 70, 0);
            let mut relocations = vec![];
            for off in [0x10, 0x1a, 0x24, 0x2e, 0x38, 0x42] {
                relocations.push(Relocation {
                    offset: temp + off,
                    addend: callback as u32,
                    controller_relative: false,
                });
            }
            let data = bytes.len();
            bytes.resize(data + 64, 0);
            let identity_data = bytes.len();
            if matches!(op, Operation::Suppress) {
                bytes.extend_from_slice(&crate::protocol::pioneer_identity());
            }
            let eligibility_callback = bytes.len();
            let mut eligibility_asm =
                Asm::new(Target::H8S2000, Mode::Advanced).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            emit_op(
                &mut eligibility_asm,
                "SUB",
                Some(Size::Long),
                Operand::Register(Reg::Long(0)),
                Operand::Register(Reg::Long(0)),
            )?; // return zero
            emit_op(
                &mut eligibility_asm,
                "RTS",
                None,
                Operand::None,
                Operand::None,
            )?;
            bytes.extend(
                eligibility_asm
                    .finish(0)
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?,
            );
            let vid_wrapper_offset = bytes.len() as u32;
            let vid_code = vid_wrapper(sites, helper, invalid)?;
            let vid_pointer =
                h8_asm::image::find(&vid_code, h8_asm::image::Needle::Word(0x00888880), 0)
                    .context("missing VID data relocation")?;
            bytes.extend_from_slice(&vid_code);
            let vid_table_offset = bytes.len() as u32;
            bytes.resize(bytes.len() + 40, 0);
            let vid_data = bytes.len();
            bytes.extend_from_slice(&[0, 0x22, 0, 0]);
            bytes.resize(bytes.len() + 32, 0);
            relocations.push(Relocation {
                offset: vid_wrapper_offset as usize + vid_pointer,
                addend: vid_data as u32,
                controller_relative: false,
            });
            let policy = bytes.len();
            let vid_policy =
                h8_asm::image::find(&vid_code, h8_asm::image::Needle::Word(0x00999990), 0)
                    .context("missing VID policy relocation")?;
            relocations.push(Relocation {
                offset: vid_wrapper_offset as usize + vid_policy,
                addend: policy as u32,
                controller_relative: false,
            });
            ensure!(
                security_table.len() == sites.table_length,
                "security table extent"
            );
            bytes.extend_from_slice(security_table);
            relocations.push(Relocation {
                offset: policy + 0x100,
                addend: eligibility_callback as u32,
                controller_relative: false,
            });
            for (marker, addend, controller_relative) in [
                (0x00111110u32, temp, false),
                (0x00333330, data, true),
                (0x00444440, identity_data, true),
                (0x00666660, policy, false),
                (0x00777770, policy, false),
            ] {
                let code = &bytes[..code_length];
                let needle = h8_asm::image::Needle::Word(marker);
                let offset = h8_asm::image::find(code, needle, 0)
                    .context("missing operation relocation marker")?;
                ensure!(
                    h8_asm::image::find(code, needle, offset + 1).is_none(),
                    "ambiguous operation relocation marker"
                );
                relocations.push(Relocation {
                    offset,
                    addend: addend as u32,
                    controller_relative,
                });
            }
            Ok(Trampoline {
                source_sha256: hash,
                bytes,
                alignment: 32,
                wrapper_offset: 0,
                table_offset,
                vid_wrapper_offset,
                vid_table_offset,
                relocations,
                mutable_state_offset: None,
            })
        }

        #[cfg(test)]
        mod tests {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/freemkv/renesas/operations_tests.rs"
            ));
        }
    }

    mod routing {
        //! Foundation-owned namespace gate. Feature implementations never handle OEM CDBs.
        use crate::freemkv::renesas::hook::firmware::{
            abs, cdb_byte, compare_byte, emit, pop, push,
        };
        use anyhow::Result;
        use h8_asm::Asm;

        pub(crate) fn enter(a: &mut Asm) -> Result<()> {
            push(a, 2)?;
            for (offset, value) in [0x3c, 0x0e, 0xc0, 0xde].into_iter().enumerate() {
                cdb_byte(a, offset)?;
                compare_byte(a, value)?;
                a.branch(6, "foundation_oem")
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            }
            Ok(())
        }
        pub(crate) fn oem(a: &mut Asm, main: u32) -> Result<()> {
            a.label("foundation_oem")
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            pop(a, 2)?;
            emit(a, &abs(0x5a, main)?)
        }
    }
}
