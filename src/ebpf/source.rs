//! `EventSource` — load BPF programs, attach kprobes, surface a channel.
//!
//! The Linux implementation lives behind `#[cfg(target_os = "linux")]` and
//! is fully fleshed out: it loads the embedded BPF object, attaches the
//! `tcp_v4_connect` kprobe, spawns a reader thread on the ring buffer,
//! and pushes decoded `EbpfEvent`s onto a `std::sync::mpsc::Receiver`.
//!
//! On non-Linux targets the same struct exists but `new()` returns
//! `Err(EbpfError::UnsupportedPlatform)`. This keeps cross-platform crates
//! that depend on `netwatch-sdk` with the `ebpf` feature enabled
//! compile-clean on macOS / Windows; only the runtime call fails.

use std::sync::mpsc::Receiver;

use super::event::EbpfEvent;

/// Errors returned from [`EventSource::new`].
#[derive(Debug)]
pub enum EbpfError {
    /// The crate was built with the `ebpf` feature but is running on a
    /// non-Linux target. eBPF is Linux-only.
    UnsupportedPlatform,
    /// The compiled BPF object isn't embedded in this build. Run
    /// `scripts/build-ebpf.sh` and rebuild with `--features ebpf`.
    BpfObjectMissing,
    /// The kernel rejected the program (verifier error, missing BTF,
    /// missing `CAP_BPF`, etc.). The wrapped string is the kernel-supplied
    /// reason where available.
    LoadFailed(String),
    /// Attaching one of the kprobes failed. Usually means the kernel
    /// symbol is missing on this kernel version.
    AttachFailed(String),
    /// The ring-buffer reader thread couldn't be spawned.
    Io(std::io::Error),
}

impl std::fmt::Display for EbpfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                write!(f, "eBPF event source is only available on Linux")
            }
            Self::BpfObjectMissing => write!(
                f,
                "BPF object not embedded; run scripts/build-ebpf.sh and \
                 rebuild netwatch-sdk with --features ebpf"
            ),
            Self::LoadFailed(s) => write!(f, "BPF load failed: {s}"),
            Self::AttachFailed(s) => write!(f, "BPF attach failed: {s}"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for EbpfError {}

impl From<std::io::Error> for EbpfError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Opaque handle to a running eBPF event source. Drop to detach all
/// programs and stop the reader thread.
pub struct EventSource {
    // On Linux this owns the loaded `aya::Bpf` and the reader thread
    // join handle. On other platforms it's empty.
    _inner: PlatformInner,
}

impl EventSource {
    /// Load and attach the eBPF programs, returning a handle plus a
    /// receiver of decoded events.
    ///
    /// On non-Linux targets this returns
    /// [`EbpfError::UnsupportedPlatform`] without side effects.
    pub fn new() -> Result<(Self, Receiver<EbpfEvent>), EbpfError> {
        platform::new()
    }
}

// ── Platform dispatch ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
type PlatformInner = linux::Inner;

#[cfg(not(target_os = "linux"))]
type PlatformInner = ();

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    pub fn new() -> Result<(EventSource, Receiver<EbpfEvent>), EbpfError> {
        super::linux::new()
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;
    pub fn new() -> Result<(EventSource, Receiver<EbpfEvent>), EbpfError> {
        Err(EbpfError::UnsupportedPlatform)
    }
}

// ── Linux implementation ─────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::ebpf::event::{estimate_boot_time, ConnectEvent};
    use aya::{maps::RingBuf, programs::KProbe, Bpf};
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread::{self, JoinHandle};

    /// The compiled BPF object, embedded at build time by `build.rs`.
    /// The build script always writes a file at `$OUT_DIR/netwatch_sdk_ebpf.o`
    /// — empty if the user hasn't run `scripts/build-ebpf.sh`. Empty
    /// content surfaces as [`EbpfError::BpfObjectMissing`] at runtime.
    const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/netwatch_sdk_ebpf.o"));

    /// Poll timeout. Bounds shutdown latency: dropping the EventSource
    /// flips the shutdown flag and the reader thread exits within at
    /// most this many milliseconds.
    const POLL_TIMEOUT_MS: i32 = 100;

    pub struct Inner {
        // aya::Bpf must outlive every attached program; dropping it detaches.
        _bpf: Bpf,
        shutdown: Arc<AtomicBool>,
        // Held only so the handle lives as long as Inner. JoinHandle's
        // default Drop detaches the thread — we deliberately don't join
        // (see Drop impl comment).
        _reader: Option<JoinHandle<()>>,
    }

    impl Drop for Inner {
        fn drop(&mut self) {
            // Signal shutdown and detach. We don't join the reader for
            // two reasons:
            //   1. On a busy host the inner ring-buffer drain can loop
            //      between shutdown checks and hold the thread indefinitely.
            //   2. aya::Bpf's own Drop (which runs after this, from the
            //      auto field-drop) closes the program fd; the reader
            //      will see its next `ring.next()` return nothing and
            //      check the flag.
            // The test process exits shortly after anyway; the thread
            // is reaped with it.
            self.shutdown.store(true, Ordering::Relaxed);
        }
    }

    pub fn new() -> Result<(EventSource, Receiver<EbpfEvent>), EbpfError> {
        if BPF_OBJECT.is_empty() {
            return Err(EbpfError::BpfObjectMissing);
        }

        // `include_bytes!` returns bytes with 1-byte alignment. aya's ELF
        // parser (the `object` crate) reads `FileHeader64` at offset 0,
        // which needs 8-byte alignment. Copy into a Vec so the allocator
        // hands us properly aligned memory.
        let object: Vec<u8> = BPF_OBJECT.to_vec();
        let mut bpf =
            Bpf::load(&object).map_err(|e| EbpfError::LoadFailed(format!("{e:?}")))?;

        // Attach kprobe.
        let program: &mut KProbe = bpf
            .program_mut("tcp_v4_connect")
            .ok_or_else(|| {
                EbpfError::LoadFailed("program tcp_v4_connect not found in BPF object".into())
            })?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| {
                EbpfError::LoadFailed(format!("not a kprobe: {e:?}"))
            })?;
        program
            .load()
            .map_err(|e| EbpfError::LoadFailed(format!("{e:?}")))?;
        program
            .attach("tcp_v4_connect", 0)
            .map_err(|e| EbpfError::AttachFailed(format!("{e:?}")))?;

        // Take ownership of the EVENTS ring buffer.
        let events_map = bpf
            .take_map("EVENTS")
            .ok_or_else(|| EbpfError::LoadFailed("EVENTS map not found".into()))?;
        let mut ring: RingBuf<_> = RingBuf::try_from(events_map)
            .map_err(|e| EbpfError::LoadFailed(format!("EVENTS not a RingBuf: {e:?}")))?;

        // Cache the ring buffer's underlying fd for poll(2). aya's RingBuf
        // is registered as a poll-friendly fd by the kernel: POLLIN
        // signals data is available.
        let ring_fd = ring.as_raw_fd();

        let (tx, rx) = mpsc::channel::<EbpfEvent>();
        let boot = estimate_boot_time();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_for_thread = shutdown.clone();

        // Reader thread blocks in poll(2) until the kernel signals data
        // is ready or the configured timeout elapses. The timeout is the
        // worst-case shutdown latency — between iterations the thread
        // checks the shutdown flag and exits cleanly.
        let reader = thread::Builder::new()
            .name("netwatch-sdk-ebpf-reader".into())
            .spawn(move || {
                use netwatch_sdk_common::{ConnectV4Event, EventKind};
                let mut pollfd = libc::pollfd {
                    fd: ring_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                loop {
                    if shutdown_for_thread.load(Ordering::Relaxed) {
                        return;
                    }

                    // SAFETY: pollfd is a valid initialised value, length 1.
                    let n = unsafe { libc::poll(&mut pollfd, 1, POLL_TIMEOUT_MS) };
                    if n < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() == Some(libc::EINTR) {
                            continue;
                        }
                        // Hard poll error — exit so we don't busy-loop on
                        // a permanently broken fd.
                        return;
                    }

                    // Always drain — `poll` returning 0 (timeout) just
                    // means no wakeup arrived; events that landed between
                    // the previous drain and the poll register are still
                    // sitting in the ring buffer. Check the shutdown
                    // flag inside the loop: on a busy host the ring
                    // buffer can stay non-empty indefinitely, and
                    // shutdown would otherwise only be observed at the
                    // next outer-loop iteration (which never comes).
                    while let Some(item) = ring.next() {
                        if shutdown_for_thread.load(Ordering::Relaxed) {
                            return;
                        }
                        let bytes = item.as_ref();
                        if bytes.is_empty() {
                            continue;
                        }
                        let kind_byte = bytes[0];
                        if kind_byte == EventKind::TcpV4Connect as u8 {
                            if bytes.len() < std::mem::size_of::<ConnectV4Event>() {
                                continue;
                            }
                            // SAFETY: the BPF program writes ConnectV4Event
                            // with #[repr(C)]; we read back the same layout.
                            let raw = unsafe {
                                std::ptr::read_unaligned(bytes.as_ptr() as *const ConnectV4Event)
                            };
                            let ev = ConnectEvent::decode(&raw, boot);
                            // Receiver dropped → exit the thread cleanly.
                            if tx.send(EbpfEvent::Connect(ev)).is_err() {
                                return;
                            }
                        }
                    }
                }
            })?;

        Ok((
            EventSource {
                _inner: Inner {
                    _bpf: bpf,
                    shutdown,
                    _reader: Some(reader),
                },
            },
            rx,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_platform_error_renders() {
        let s = format!("{}", EbpfError::UnsupportedPlatform);
        assert!(s.contains("Linux"));
    }

    #[test]
    fn bpf_object_missing_error_explains_fix() {
        let s = format!("{}", EbpfError::BpfObjectMissing);
        assert!(s.contains("scripts/build-ebpf.sh"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn new_on_non_linux_returns_unsupported() {
        let result = EventSource::new();
        assert!(matches!(result, Err(EbpfError::UnsupportedPlatform)));
    }
}
