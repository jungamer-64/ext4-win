//! ETW session ownership: native stop, consumer close, worker join, loss checks, then completion.
use super::{guid_bytes, wide, win32};
use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
use core::ptr;
use std::{
    ffi::OsStr,
    fs, io,
    path::Path,
    sync::Mutex,
    thread::{self, JoinHandle},
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::{Win32::System::Diagnostics::Etw::*, core::GUID};

/// One fixed-scalar event projected from the checked-in provider schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceEvent {
    /// Contract event name, never a filesystem path.
    pub event: String,
    /// Native status bits.
    pub status: u32,
    /// Contract outcome name.
    pub outcome: String,
}
/// Bounded recent-event projection and first consumer failure; ETL remains the trace artifact.
#[derive(Debug, Default)]
struct Records {
    /// Last 1024 events, not an independent full trace authority.
    recent: VecDeque<TraceEvent>,
    /// First malformed record or output error.
    failure: Option<String>,
}
/// Stable callback storage retained by the owner and by the native consumer worker.
struct Context {
    /// Selected provider identity.
    provider: GUID,
    /// Schema event names keyed by native ID.
    events: BTreeMap<u16, String>,
    /// Schema outcome names keyed by native value.
    outcomes: BTreeMap<u32, String>,
    /// Consumer-owned output projection.
    records: Mutex<Records>,
}
/// Properly aligned native property storage, including the two trailing terminated strings.
#[repr(C)]
struct Properties {
    /// Native property structure at offset zero.
    header: EVENT_TRACE_PROPERTIES,
    /// Session name storage.
    name: [u16; 128],
    /// ETL filename storage.
    file: [u16; 1024],
}
/// Owned native ETW session and its observed consumer worker.
pub struct TraceSession {
    /// Storage borrowed only during synchronous control calls.
    properties: Box<Properties>,
    /// Native controller authority while the session is live.
    session: Option<CONTROLTRACE_HANDLE>,
    /// Native consumer authority until explicit close.
    consumer: Option<PROCESSTRACE_HANDLE>,
    /// Completion observer; no worker is detached.
    worker: Option<JoinHandle<u32>>,
    /// Shared stable callback storage, also retained by worker.
    context: Arc<Context>,
}
impl core::fmt::Debug for TraceSession {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TraceSession")
            .field("controller_active", &self.session.is_some())
            .field("consumer_active", &self.consumer.is_some())
            .field("worker_active", &self.worker.is_some())
            .finish_non_exhaustive()
    }
}

/// Copies a terminated native boundary string into fixed aligned property storage.
/// # Errors
/// Returns an error for excessive string lengths.
fn store(destination: &mut [u16], source: &[u16]) -> io::Result<()> {
    let destination = destination
        .get_mut(..source.len())
        .ok_or_else(|| io::Error::other("ETW property string exceeds capacity"))?;
    for (destination, source) in destination.iter_mut().zip(source) {
        *destination = *source;
    }
    Ok(())
}
/// Converts Windows native GUID bytes into the canonical binding value.
/// # Errors
/// Returns invalid GUID fields.
fn guid(value: &str) -> io::Result<GUID> {
    let bytes = guid_bytes(value)?;
    let d1 = u32::from_le_bytes(
        bytes
            .get(..4)
            .ok_or_else(|| io::Error::other("GUID field"))?
            .try_into()
            .map_err(io::Error::other)?,
    );
    let d2 = u16::from_le_bytes(
        bytes
            .get(4..6)
            .ok_or_else(|| io::Error::other("GUID field"))?
            .try_into()
            .map_err(io::Error::other)?,
    );
    let d3 = u16::from_le_bytes(
        bytes
            .get(6..8)
            .ok_or_else(|| io::Error::other("GUID field"))?
            .try_into()
            .map_err(io::Error::other)?,
    );
    Ok(GUID {
        data1: d1,
        data2: d2,
        data3: d3,
        data4: bytes
            .get(8..)
            .ok_or_else(|| io::Error::other("GUID field"))?
            .try_into()
            .map_err(io::Error::other)?,
    })
}

impl TraceSession {
    /// Starts one fixed-scalar provider session before the driver/provider is registered.
    /// # Errors
    /// Returns schema, native session, output path, or consumer initialization errors.
    pub fn start(contract: &Path, directory: &Path) -> io::Result<Self> {
        let mut records = BTreeMap::new();
        for line in fs::read_to_string(contract)?.lines() {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| io::Error::other("malformed trace schema"))?;
            if records.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(io::Error::other("duplicate trace schema key"));
            }
        }
        if records.get("contract_version").map(String::as_str) != Some("1") {
            return Err(io::Error::other("unsupported trace schema"));
        }
        let provider = guid(
            records
                .get("provider_guid")
                .ok_or_else(|| io::Error::other("provider identity absent"))?,
        )?;
        let mut events = BTreeMap::new();
        let mut outcomes = BTreeMap::new();
        for (key, value) in &records {
            if let Some(name) = key.strip_prefix("event_")
                && events
                    .insert(
                        value.parse::<u16>().map_err(io::Error::other)?,
                        name.to_owned(),
                    )
                    .is_some()
            {
                return Err(io::Error::other("duplicate trace event ID"));
            }
            if let Some(name) = key.strip_prefix("outcome_")
                && outcomes
                    .insert(
                        value.parse::<u32>().map_err(io::Error::other)?,
                        name.to_owned(),
                    )
                    .is_some()
            {
                return Err(io::Error::other("duplicate trace outcome"));
            }
        }
        let context = Arc::new(Context {
            provider,
            events,
            outcomes,
            records: Mutex::new(Records::default()),
        });
        let instant = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let name = format!("ext4win-live-{}-{instant}", std::process::id());
        fs::create_dir_all(directory)?;
        let filename = directory.canonicalize()?.join(format!("{name}.etl"));
        let mut properties = Box::try_new(Properties {
            header: EVENT_TRACE_PROPERTIES::default(),
            name: [0; 128],
            file: [0; 1024],
        })
        .map_err(io::Error::other)?;
        store(&mut properties.name, &wide(OsStr::new(&name))?)?;
        store(&mut properties.file, &wide(filename.as_os_str())?)?;
        properties.header.Wnode.BufferSize =
            u32::try_from(core::mem::size_of::<Properties>()).map_err(io::Error::other)?;
        properties.header.Wnode.Guid = GUID::from_u128(instant);
        properties.header.Wnode.ClientContext = 1;
        properties.header.Wnode.Flags = 0x0002_0000;
        properties.header.BufferSize = 16;
        properties.header.MinimumBuffers = 4;
        properties.header.MaximumBuffers = 16;
        properties.header.MaximumFileSize = 16;
        properties.header.LogFileMode = 0x102;
        properties.header.FlushTimer = 1;
        properties.header.LoggerNameOffset =
            u32::try_from(core::mem::offset_of!(Properties, name)).map_err(io::Error::other)?;
        properties.header.LogFileNameOffset =
            u32::try_from(core::mem::offset_of!(Properties, file)).map_err(io::Error::other)?;
        let mut session = CONTROLTRACE_HANDLE::default();
        let status = unsafe {
            // SAFETY: aligned property storage covers the advertised trailing strings and stays alive through the call.
            StartTraceW(
                &mut session,
                properties.name.as_ptr(),
                &mut properties.header,
            )
        };
        win32(status)?;
        let mut owner = Self {
            properties,
            session: Some(session),
            consumer: None,
            worker: None,
            context,
        };
        let status = unsafe {
            // SAFETY: the controller handle is live and provider identity remains valid; no callback parameters are borrowed.
            EnableTraceEx2(session, &owner.context.provider, 1, 5, 0, 0, 0, ptr::null())
        };
        win32(status)?;
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: owner.properties.name.as_mut_ptr(),
            Context: Arc::as_ptr(&owner.context).cast_mut().cast(),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode = 0x1000_0100;
        logfile.Anonymous2.EventRecordCallback = Some(event);
        let consumer = unsafe {
            // SAFETY: logfile points to initialized schema context retained by the owner and, before processing, the worker.
            OpenTraceW(&mut logfile)
        };
        if consumer.Value == u64::MAX {
            return Err(io::Error::last_os_error());
        }
        owner.consumer = Some(consumer);
        let retained = Arc::clone(&owner.context);
        owner.worker = Some(thread::Builder::new().name("ext4win-etw".into()).spawn(
            move || {
                let status = unsafe {
                    // SAFETY: the worker's Arc retains callback context through ProcessTrace and consumer authority is closed only by its owner.
                    ProcessTrace(&consumer, 1, ptr::null(), ptr::null())
                };
                drop(retained);
                status
            },
        )?);
        println!("operational ETW capture: {}", filename.display());
        Ok(owner)
    }

    /// Stops capture, closes the native consumer, joins its worker and rejects record/buffer loss.
    /// # Errors
    /// Returns controller, consumer, callback, worker or lost-event failures. Completion is
    /// synchronous; worker termination is observed before callback storage can be released.
    pub fn finish(mut self) -> io::Result<Vec<TraceEvent>> {
        self.stop()?;
        self.context
            .records
            .lock()
            .map_err(|_| io::Error::other("ETW output lock poisoned"))
            .map(|records| records.recent.iter().cloned().collect())
    }

    /// Consumes every live native/worker authority even when one completion boundary fails.
    /// # Errors
    /// Returns all collected teardown errors after the worker has been joined.
    fn stop(&mut self) -> io::Result<()> {
        let mut failures = Vec::new();
        if let Some(session) = self.session.take() {
            let status = unsafe {
                // SAFETY: this owner consumes the live controller; property storage remains aligned and alive.
                ControlTraceW(
                    session,
                    self.properties.name.as_ptr(),
                    &mut self.properties.header,
                    1,
                )
            };
            if let Err(error) = win32(status) {
                failures.push(error.to_string());
            }
        }
        if let Some(consumer) = self.consumer.take() {
            let status = unsafe {
                // SAFETY: the owner consumes its consumer once; callback context remains retained until worker join.
                CloseTrace(consumer)
            };
            if status != 7007
                && let Err(error) = win32(status)
            {
                failures.push(error.to_string());
            }
        }
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(0 | 1223) => {}
                Ok(status) => failures.push(format!("ProcessTrace failed with {status}")),
                Err(_) => failures.push("ETW consumer worker panicked".into()),
            }
        }
        let properties = &self.properties.header;
        if properties.EventsLost != 0
            || properties.LogBuffersLost != 0
            || properties.RealTimeBuffersLost != 0
        {
            failures.push("ETW capture lost events or buffers".into());
        }
        match self.context.records.lock() {
            Ok(records) => {
                if let Some(failure) = &records.failure {
                    failures.push(failure.clone());
                }
            }
            Err(_) => failures.push("ETW output lock poisoned".into()),
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(failures.join("; ")))
        }
    }
}
impl Drop for TraceSession {
    /// Reclaims an abandoned session without detaching the native consumer worker.
    fn drop(&mut self) {
        if (self.session.is_some() || self.consumer.is_some() || self.worker.is_some())
            && let Err(error) = self.stop()
        {
            eprintln!("ETW fallback completion failed: {error}");
        }
    }
}

/// Copies exactly the schema's two scalar fields while Windows owns the event record.
/// # Safety
/// ETW must supply a live EVENT_RECORD with the registered Context pointer retained by the
/// owner/worker Arc and readable UserData for UserDataLength bytes for this callback only.
unsafe extern "system" fn event(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let record = unsafe {
        // SAFETY: ETW's callback contract guarantees the record lifetime for this invocation.
        &*record
    };
    if record.UserContext.is_null() {
        return;
    }
    let context = unsafe {
        // SAFETY: the owner installed this stable Arc allocation and the worker retains it through native processing.
        &*record.UserContext.cast::<Context>()
    };
    let provider = &record.EventHeader.ProviderId;
    if provider.data1 != context.provider.data1
        || provider.data2 != context.provider.data2
        || provider.data3 != context.provider.data3
        || provider.data4 != context.provider.data4
    {
        return;
    }
    let result = (|| -> io::Result<TraceEvent> {
        if record.UserDataLength != 8 || record.UserData.is_null() {
            return Err(io::Error::other("ETW scalar payload length mismatch"));
        }
        let bytes = unsafe {
            // SAFETY: the callback contract provides eight readable payload bytes for this callback; they are copied immediately.
            ptr::read_unaligned(record.UserData.cast::<[u8; 8]>())
        };
        let status = u32::from_le_bytes(super::field(&bytes, 0)?);
        let outcome = u32::from_le_bytes(super::field(&bytes, 4)?);
        let event = context
            .events
            .get(&record.EventHeader.EventDescriptor.Id)
            .ok_or_else(|| io::Error::other("unknown trace event ID"))?
            .clone();
        let outcome = context
            .outcomes
            .get(&outcome)
            .ok_or_else(|| io::Error::other("unknown trace outcome"))?
            .clone();
        Ok(TraceEvent {
            event,
            status,
            outcome,
        })
    })();
    if let Ok(mut records) = context.records.lock() {
        match result {
            Ok(event) => {
                use std::io::Write as _;
                if let Err(error) = writeln!(
                    io::stdout().lock(),
                    "kernel {}: {} NTSTATUS=0x{:08X}",
                    event.event,
                    event.outcome,
                    event.status
                ) {
                    records.failure.get_or_insert_with(|| error.to_string());
                }
                if records.recent.len() == 1024 {
                    records.recent.pop_front();
                }
                records.recent.push_back(event);
            }
            Err(error) => {
                records.failure.get_or_insert_with(|| error.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;
    use std::time::Instant;

    /// Exercises the real ETW ABI, enable-before-registration, scalar delivery and joined shutdown.
    /// # Errors
    /// Returns schema, native provider/session, delivery, artifact or explicit cleanup failures.
    /// # Panics
    /// Panics if the independent provider's three scalar records are decoded incorrectly.
    #[test]
    #[ignore = "requires an elevated Windows ETW host; cargo xtask verify-windows-host runs this required platform gate"]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "independent provider assertions intentionally fail the ABI contract test"
    )]
    fn native_etw_contract() -> io::Result<()> {
        super::super::require_administrator()?;
        let instant = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("ext4win-etw-test-{}-{instant}", std::process::id()));
        fs::create_dir(&directory)?;
        let operation = (|| -> io::Result<()> {
            let provider_name = format!(
                "01234567-89ab-cdef-0123-{:012x}",
                instant & 0xffff_ffff_ffff
            );
            let provider = guid(&provider_name)?;
            let contract = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../crates/ext4-driver/operational-trace-v1.txt");
            let schema = fs::read_to_string(contract)?
                .lines()
                .map(|line| {
                    if line.starts_with("provider_guid=") {
                        format!("provider_guid={provider_name}\n")
                    } else {
                        format!("{line}\n")
                    }
                })
                .collect::<String>();
            let contract = directory.join("contract.txt");
            fs::write(&contract, schema)?;
            let capture = TraceSession::start(&contract, &directory)?;
            let mut registration = 0;
            let status = unsafe {
                // SAFETY: provider/output storage is valid for this synchronous registration;
                // no callback or borrowed context is registered.
                EventRegister(&provider, None, ptr::null(), &mut registration)
            };
            let result = (|| -> io::Result<()> {
                win32(status)?;
                for payload in [[0_u32, 1], [0xc000_000d, 4], [0, 2]] {
                    let data = EVENT_DATA_DESCRIPTOR {
                        Ptr: u64::try_from(payload.as_ptr().addr()).map_err(io::Error::other)?,
                        Size: 8,
                        ..Default::default()
                    };
                    let descriptor = EVENT_DESCRIPTOR {
                        Id: 18,
                        Level: 4,
                        Keyword: 1,
                        ..Default::default()
                    };
                    let status = unsafe {
                        // SAFETY: registration is live and the descriptor references exactly
                        // eight initialized payload bytes retained through synchronous EventWrite.
                        EventWrite(registration, &descriptor, 1, &data)
                    };
                    win32(status)?;
                }
                let start = Instant::now();
                loop {
                    let count = capture
                        .context
                        .records
                        .lock()
                        .map_err(|_| io::Error::other("ETW test observation poisoned"))?
                        .recent
                        .len();
                    if count == 3 {
                        break;
                    }
                    if start.elapsed() > Duration::from_secs(10) {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "independent ETW records were not delivered",
                        ));
                    }
                    thread::sleep(Duration::from_millis(25));
                }
                Ok(())
            })();
            let unregister = if registration != 0 {
                let status = unsafe {
                    // SAFETY: this test uniquely consumes its successfully registered provider.
                    EventUnregister(registration)
                };
                win32(status)
            } else {
                Ok(())
            };
            let completion = capture.finish();
            result?;
            unregister?;
            let records = completion?;
            assert_eq!(
                records
                    .iter()
                    .map(|event| (event.event.as_str(), event.status, event.outcome.as_str()))
                    .collect::<Vec<_>>(),
                [
                    ("driver_initialization", 0, "selected"),
                    ("driver_initialization", 0xc000_000d, "failed"),
                    ("driver_initialization", 0, "completed")
                ]
            );
            assert_eq!(
                fs::read_dir(&directory)?
                    .collect::<io::Result<Vec<_>>>()?
                    .into_iter()
                    .filter(|entry| entry.path().extension() == Some(OsStr::new("etl")))
                    .count(),
                1
            );
            Ok(())
        })();
        let cleanup = (|| -> io::Result<()> {
            for entry in fs::read_dir(&directory)? {
                fs::remove_file(entry?.path())?;
            }
            fs::remove_dir(&directory)
        })();
        match (operation, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(io::Error::other(format!(
                "{error}; ETW test cleanup: {cleanup}"
            ))),
        }
    }
}
