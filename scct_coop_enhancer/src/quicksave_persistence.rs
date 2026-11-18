use anyhow::{Context, Result};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SAVE_PAIRS: [(&str, &str); 2] = [
    ("CacheCoopQuickSaveHost.sav", "host"),
    ("CacheCoopQuickSaveClient.sav", "client"),
];
const DEFAULT_SETTLE_DELAY: Duration = Duration::from_millis(120);
const MAX_SETTLE_ATTEMPTS: usize = 15;
#[cfg(any(windows, test))]
const QUICKSAVE_ALLOC_SIZE: usize = 0x1000;
#[cfg(any(windows, test))]
const QUICKSAVE_CODE_LIMIT: usize = 0x200;
#[cfg(any(windows, test))]
const FMT_HOST_OFFSET: u32 = 0x200;
#[cfg(any(windows, test))]
const FMT_CLIENT_OFFSET: u32 = 0x240;

#[cfg(any(windows, test))]
const FN_FSTRING_ASSIGN: u32 = 0x1090_97E0;
#[cfg(any(windows, test))]
const FN_FSTRING_FROM_WSTR: u32 = 0x1090_BA00;
#[cfg(any(windows, test))]
const FN_FSTRING_DTOR: u32 = 0x1090_BA70;
#[cfg(any(windows, test))]
const FN_IS_COOP_HOST: u32 = 0x1095_B880;
#[cfg(any(windows, test))]
const FN_APP_SNWPRINTF_400: u32 = 0x10CC_B0D0;
#[cfg(any(windows, test))]
const PTR_FILE_MANAGER_VA: u32 = 0x111C_88A4;
#[cfg(any(windows, test))]
const PTR_SAVE_CFG_VA: u32 = 0x1123_0570;

#[cfg(any(windows, test))]
pub const HOOK_COOP_QUICKLOAD_LEN_VA: u32 = 0x10B2_3919;
#[cfg(any(windows, test))]
pub const HOOK_COOP_QUICKLOAD_LEN_RESUME_VA: u32 = 0x10B2_391F;
#[cfg(any(windows, test))]
pub const HOOK_COOP_QUICKLOAD_LEN_ORIG: [u8; 6] = [0x8B, 0x80, 0xE4, 0x00, 0x00, 0x00];

#[cfg(any(windows, test))]
pub const HOOK_PAUSE_QUICKLOAD_VA: u32 = 0x10B2_8732;
#[cfg(any(windows, test))]
pub const HOOK_PAUSE_QUICKLOAD_RESUME_VA: u32 = 0x10B2_8738;
#[cfg(any(windows, test))]
pub const HOOK_PAUSE_QUICKLOAD_ORIG: [u8; 6] = [0x8A, 0x88, 0xEC, 0x0F, 0x00, 0x00];

#[cfg(any(windows, test))]
pub const HOOK_GAMEOVER_QUICKLOAD_VA: u32 = 0x10B2_9EB8;
#[cfg(any(windows, test))]
pub const HOOK_GAMEOVER_QUICKLOAD_RESUME_VA: u32 = 0x10B2_9EBE;
#[cfg(any(windows, test))]
pub const HOOK_GAMEOVER_QUICKLOAD_ORIG: [u8; 6] = [0x8A, 0x88, 0xEC, 0x0F, 0x00, 0x00];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QuickSaveSyncReport {
    pub backed_up_count: usize,
    pub restored_count: usize,
    pub profile_dir: PathBuf,
    pub backup_dir: PathBuf,
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuickSaveHookOffsets {
    pub stub_pause_va: u32,
    pub stub_gameover_va: u32,
    pub stub_quickload_va: u32,
}

enum WorkerCommand {
    Flush(Sender<Result<QuickSaveSyncReport>>),
    Stop,
}

pub struct PersistentQuickSaveHandle {
    game_root: PathBuf,
    cmd_tx: Sender<WorkerCommand>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl std::fmt::Debug for PersistentQuickSaveHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistentQuickSaveHandle")
            .field("game_root", &self.game_root)
            .finish_non_exhaustive()
    }
}

impl PersistentQuickSaveHandle {
    pub fn game_root(&self) -> &Path {
        &self.game_root
    }

    /// Triggers an immediate settled snapshot on the background worker and waits for completion.
    pub fn flush(&self) -> Result<QuickSaveSyncReport> {
        let (tx, rx) = channel();
        if self.cmd_tx.send(WorkerCommand::Flush(tx)).is_err() {
            return snapshot_quick_saves_for_persistence(&self.game_root);
        }
        match rx.recv_timeout(Duration::from_secs(4)) {
            Ok(result) => result,
            Err(_) => snapshot_quick_saves_for_persistence(&self.game_root),
        }
    }

    pub fn stop(&mut self) {
        let _ = self.cmd_tx.send(WorkerCommand::Stop);
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for PersistentQuickSaveHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn find_scct_quicksave_profile_dir(game_root: &Path) -> Option<PathBuf> {
    let local_appdata = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE").map(|home| PathBuf::from(home).join(r"AppData\Local"))
        })?;

    let mut candidates = Vec::new();
    candidates.push(local_appdata.join("Ubisoft"));

    if let Some(game_name) = game_root.file_name() {
        candidates.push(local_appdata.join("Ubisoft").join(game_name));
        candidates.push(
            local_appdata
                .join("Ubisoft")
                .join("Tom Clancy's Splinter Cell Chaos Theory"),
        );
    }

    for candidate in candidates {
        if candidate.exists() && candidate.is_dir() {
            let has_save_files = SAVE_PAIRS
                .iter()
                .any(|(live_name, _)| candidate.join(live_name).exists());
            if has_save_files {
                return Some(candidate);
            }
        }
    }

    let guessed = local_appdata
        .join("Ubisoft")
        .join("Tom Clancy's Splinter Cell Chaos Theory");
    if guessed.exists() || guessed.parent().is_some() {
        return Some(guessed);
    }

    None
}

pub fn ensure_quick_save_backup_dir(game_root: &Path) -> PathBuf {
    let root = game_root.join("scct_quicksave_backups");
    let _ = std::fs::create_dir_all(&root);
    root
}

fn is_transient_lock_error(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::PermissionDenied
        || matches!(err.raw_os_error(), Some(32) | Some(33))
}

/// Reads `source` only after its size and modification timestamp remain unchanged across
/// `settle_delay`, preventing torn mid-write snapshots while the game is flushing to disk.
fn read_settled_quicksave(
    source: &Path,
    settle_delay: Duration,
) -> Result<Option<(Vec<u8>, SystemTime)>> {
    for _ in 0..MAX_SETTLE_ATTEMPTS {
        let meta1 = match std::fs::metadata(source) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) if is_transient_lock_error(&err) => {
                if !settle_delay.is_zero() {
                    thread::sleep(settle_delay);
                }
                continue;
            }
            Err(err) => {
                return Err(err).with_context(|| format!("Reading metadata {}", source.display()));
            }
        };

        let len1 = meta1.len();
        let mtime1 = meta1.modified().unwrap_or(UNIX_EPOCH);
        if !settle_delay.is_zero() {
            thread::sleep(settle_delay);
        }

        let meta2 = match std::fs::metadata(source) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) if is_transient_lock_error(&err) => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("Reading metadata {}", source.display()));
            }
        };

        let len2 = meta2.len();
        let mtime2 = meta2.modified().unwrap_or(UNIX_EPOCH);
        if len1 == 0 || len2 == 0 || len1 != len2 || mtime1 != mtime2 {
            continue;
        }

        let contents = match std::fs::read(source) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) if is_transient_lock_error(&err) => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("Reading quick save {}", source.display()));
            }
        };

        let meta3 = match std::fs::metadata(source) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) if is_transient_lock_error(&err) => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("Verifying {}", source.display()));
            }
        };

        if contents.len() as u64 == meta3.len()
            && meta3.len() == len2
            && meta3.modified().unwrap_or(UNIX_EPOCH) == mtime2
        {
            return Ok(Some((contents, mtime2)));
        }
    }

    Ok(None)
}

fn write_file_atomic(target: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Creating directory {}", parent.display()))?;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("quicksave");
    let tmp = target.with_file_name(format!(".{file_name}.{}.{nanos}.tmp", std::process::id()));
    std::fs::write(&tmp, contents)
        .with_context(|| format!("Writing temp file {}", tmp.display()))?;
    if let Err(err) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err).with_context(|| {
            format!("Renaming {} to {}", tmp.display(), target.display())
        });
    }
    Ok(())
}

fn prune_old_backups(backup_dir: &Path, prefix: &str) -> Result<()> {
    let latest_name = format!("{prefix}_latest.sav");
    let prefix = format!("{prefix}_");
    let mut backups = std::fs::read_dir(backup_dir)
        .with_context(|| format!("Reading {}", backup_dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name != latest_name && name.starts_with(&prefix) && name.ends_with(".sav")
                })
        })
        .collect::<Vec<_>>();

    backups.sort_by(|left, right| {
        let modified = |path: &Path| {
            std::fs::metadata(path)
                .and_then(|metadata| metadata.modified())
                .unwrap_or(UNIX_EPOCH)
        };
        modified(right)
            .cmp(&modified(left))
            .then_with(|| right.cmp(left))
    });

    for old_backup in backups.into_iter().skip(3) {
        std::fs::remove_file(&old_backup)
            .with_context(|| format!("Removing old backup {}", old_backup.display()))?;
    }

    Ok(())
}

fn is_live_newer_or_unbacked(source: &Path, latest: &Path) -> bool {
    let Ok(src_meta) = std::fs::metadata(source) else {
        return false;
    };
    if src_meta.len() == 0 {
        return false;
    }
    let Ok(lat_meta) = std::fs::metadata(latest) else {
        return true;
    };
    if lat_meta.len() == 0 {
        return true;
    }
    src_meta.modified().unwrap_or(UNIX_EPOCH) > lat_meta.modified().unwrap_or(UNIX_EPOCH)
}

fn snapshot_single_quick_save(
    source: &Path,
    backup_dir: &Path,
    prefix: &str,
    ts_nanos: u128,
    settle_delay: Duration,
    only_if_newer: bool,
) -> Result<bool> {
    let latest = backup_dir.join(format!("{prefix}_latest.sav"));
    if only_if_newer && !is_live_newer_or_unbacked(source, &latest) {
        prune_old_backups(backup_dir, prefix)?;
        return Ok(false);
    }

    let Some((contents, _mtime)) = read_settled_quicksave(source, settle_delay)? else {
        prune_old_backups(backup_dir, prefix)?;
        return Ok(false);
    };

    let latest_contents = std::fs::read(&latest).ok();
    let changed = latest_contents.as_deref() != Some(contents.as_slice());
    if changed {
        let stamped = backup_dir.join(format!("{prefix}_{ts_nanos}.sav"));
        write_file_atomic(&stamped, &contents)
            .with_context(|| format!("Writing backup {}", stamped.display()))?;
        write_file_atomic(&latest, &contents)
            .with_context(|| format!("Updating latest backup {}", latest.display()))?;
    }
    prune_old_backups(backup_dir, prefix)?;
    Ok(changed)
}

fn snapshot_quick_saves_with_delay(
    profile_dir: &Path,
    backup_dir: &Path,
    settle_delay: Duration,
    only_if_newer: bool,
) -> Result<usize> {
    std::fs::create_dir_all(backup_dir)
        .with_context(|| format!("Creating {}", backup_dir.display()))?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    let mut backed_up_count = 0usize;
    for (source_name, prefix) in SAVE_PAIRS {
        let source = profile_dir.join(source_name);
        if snapshot_single_quick_save(
            &source,
            backup_dir,
            prefix,
            ts,
            settle_delay,
            only_if_newer,
        )? {
            backed_up_count += 1;
        }
    }
    Ok(backed_up_count)
}

pub fn snapshot_quick_saves_for_persistence(game_root: &Path) -> Result<QuickSaveSyncReport> {
    let profile_dir = find_scct_quicksave_profile_dir(game_root)
        .context("Could not locate the SCCT quick-save profile directory")?;
    let backup_dir = ensure_quick_save_backup_dir(game_root);
    let backed_up_count = snapshot_quick_saves_with_delay(
        &profile_dir,
        &backup_dir,
        DEFAULT_SETTLE_DELAY,
        true,
    )?;
    Ok(QuickSaveSyncReport {
        backed_up_count,
        restored_count: 0,
        profile_dir,
        backup_dir,
    })
}

fn restore_quick_saves_from_dirs_with_delay(
    profile_dir: &Path,
    backup_dir: &Path,
    settle_delay: Duration,
) -> Result<(usize, usize)> {
    std::fs::create_dir_all(profile_dir)
        .with_context(|| format!("Creating {}", profile_dir.display()))?;
    std::fs::create_dir_all(backup_dir)
        .with_context(|| format!("Creating {}", backup_dir.display()))?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    let mut backed_up_count = 0usize;
    let mut restored_count = 0usize;

    for (live_name, prefix) in SAVE_PAIRS {
        let latest = backup_dir.join(format!("{prefix}_latest.sav"));
        let target = profile_dir.join(live_name);

        if snapshot_single_quick_save(&target, backup_dir, prefix, ts, settle_delay, true)? {
            backed_up_count += 1;
        }

        let Ok(latest_bytes) = std::fs::read(&latest) else {
            continue;
        };
        if latest_bytes.is_empty() {
            continue;
        }

        let target_matches = std::fs::read(&target)
            .ok()
            .is_some_and(|cur| cur == latest_bytes);
        if !target_matches {
            write_file_atomic(&target, &latest_bytes).with_context(|| {
                format!("Restoring {} to {}", latest.display(), target.display())
            })?;
            restored_count += 1;
        }
    }

    Ok((backed_up_count, restored_count))
}

pub fn restore_latest_quick_saves(game_root: &Path) -> Result<QuickSaveSyncReport> {
    let profile_dir = find_scct_quicksave_profile_dir(game_root)
        .context("Could not locate the SCCT quick-save profile directory")?;
    let backup_dir = ensure_quick_save_backup_dir(game_root);
    let (backed_up_count, restored_count) = restore_quick_saves_from_dirs_with_delay(
        &profile_dir,
        &backup_dir,
        DEFAULT_SETTLE_DELAY,
    )?;
    Ok(QuickSaveSyncReport {
        backed_up_count,
        restored_count,
        profile_dir,
        backup_dir,
    })
}

fn is_save_event(event: &Event) -> bool {
    event.paths.iter().any(|path| {
        path.file_name().and_then(|n| n.to_str()).is_some_and(|name| {
            SAVE_PAIRS
                .iter()
                .any(|(live_name, _)| *live_name == name)
        })
    })
}

fn attach_watcher(profile_dir: &Path) -> (Option<RecommendedWatcher>, Receiver<()>) {
    let (event_tx, event_rx) = channel::<()>();
    let watcher = RecommendedWatcher::new(
        move |res: notify::Result<Event>| {
            if let Ok(event) = res
                && matches!(
                    event.kind,
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Access(_)
                )
                && is_save_event(&event)
            {
                let _ = event_tx.send(());
            }
        },
        Config::default(),
    )
    .ok()
    .and_then(|mut w| {
        w.watch(profile_dir, RecursiveMode::NonRecursive)
            .ok()
            .map(|()| w)
    });
    (watcher, event_rx)
}

pub fn spawn_quicksave_persistence(game_root: PathBuf) -> PersistentQuickSaveHandle {
    let (cmd_tx, cmd_rx) = channel::<WorkerCommand>();
    let worker_root = game_root.clone();

    let join_handle = thread::spawn(move || {
        let profile_dir = match find_scct_quicksave_profile_dir(&worker_root) {
            Some(dir) => dir,
            None => {
                while let Ok(cmd) = cmd_rx.recv() {
                    match cmd {
                        WorkerCommand::Flush(tx) => {
                            let _ = tx.send(snapshot_quick_saves_for_persistence(&worker_root));
                        }
                        WorkerCommand::Stop => break,
                    }
                }
                return;
            }
        };

        let _ = std::fs::create_dir_all(&profile_dir);
        let backup_dir = ensure_quick_save_backup_dir(&worker_root);
        let _ = snapshot_quick_saves_with_delay(
            &profile_dir,
            &backup_dir,
            DEFAULT_SETTLE_DELAY,
            true,
        );

        let (_watcher, event_rx) = attach_watcher(&profile_dir);
        let mut last_snapshot = Instant::now();
        let mut saw_live_write_event = false;

        loop {
            match cmd_rx.try_recv() {
                Ok(WorkerCommand::Flush(tx)) => {
                    while event_rx.try_recv().is_ok() {
                        saw_live_write_event = true;
                    }
                    let res = snapshot_quick_saves_with_delay(
                        &profile_dir,
                        &backup_dir,
                        DEFAULT_SETTLE_DELAY,
                        !saw_live_write_event,
                    )
                    .map(|backed_up_count| QuickSaveSyncReport {
                        backed_up_count,
                        restored_count: 0,
                        profile_dir: profile_dir.clone(),
                        backup_dir: backup_dir.clone(),
                    });
                    last_snapshot = Instant::now();
                    let _ = tx.send(res);
                }
                Ok(WorkerCommand::Stop) => {
                    while event_rx.try_recv().is_ok() {
                        saw_live_write_event = true;
                    }
                    let _ = snapshot_quick_saves_with_delay(
                        &profile_dir,
                        &backup_dir,
                        DEFAULT_SETTLE_DELAY,
                        !saw_live_write_event,
                    );
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    let _ = snapshot_quick_saves_with_delay(
                        &profile_dir,
                        &backup_dir,
                        DEFAULT_SETTLE_DELAY,
                        !saw_live_write_event,
                    );
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }

            if event_rx.recv_timeout(Duration::from_millis(80)).is_ok() {
                saw_live_write_event = true;
                while event_rx.try_recv().is_ok() {}
                let _ = snapshot_quick_saves_with_delay(
                    &profile_dir,
                    &backup_dir,
                    DEFAULT_SETTLE_DELAY,
                    false,
                );
                last_snapshot = Instant::now();
                continue;
            }

            if last_snapshot.elapsed() >= Duration::from_secs(5) {
                let _ = snapshot_quick_saves_with_delay(
                    &profile_dir,
                    &backup_dir,
                    DEFAULT_SETTLE_DELAY,
                    true,
                );
                last_snapshot = Instant::now();
            }
        }
    });

    PersistentQuickSaveHandle {
        game_root,
        cmd_tx,
        join_handle: Some(join_handle),
    }
}

#[cfg(any(windows, test))]
fn encode_utf16le_nul(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(any(windows, test))]
fn emit_menu_enable_stub(
    a: &mut crate::trace::AsmBuilder,
    resume_label: &'static str,
    resume_va: u32,
) {
    // mov cl, byte ptr [eax + 0xFEC]
    a.emit(&[0x8A, 0x88, 0xEC, 0x0F, 0x00, 0x00]);
    // test cl, cl
    a.emit(&[0x84, 0xC9]);
    // jne resume
    a.jcc_rel8(0x75, resume_label);
    // push eax; push edx; push 0
    a.emit(&[0x50, 0x52, 0x6A, 0x00]);
    a.call_label("resolve_quicksave");
    // mov cl, al; pop edx; pop eax
    a.emit(&[0x88, 0xC1, 0x5A, 0x58]);
    // test cl, cl; je resume
    a.emit(&[0x84, 0xC9]);
    a.jcc_rel8(0x74, resume_label);
    // mov byte ptr [eax + 0xFEC], 1
    a.emit(&[0xC6, 0x80, 0xEC, 0x0F, 0x00, 0x00, 0x01]);
    a.label(resume_label);
    a.jmp_external(resume_va);
}

/// Builds the executable RWX page enabling restored `CacheCoopQuickSave*.sav` files
/// to be loaded via Pause / Game Over -> Quick Load even on a fresh game launch.
#[cfg(any(windows, test))]
pub fn build_quicksave_hook_page(base_va: u32) -> (Vec<u8>, QuickSaveHookOffsets) {
    let fmt_host_va = base_va + FMT_HOST_OFFSET;
    let fmt_client_va = base_va + FMT_CLIENT_OFFSET;
    let mut a = crate::trace::AsmBuilder::with_limit(base_va, QUICKSAVE_CODE_LIMIT);

    // -------------------------------------------------------------------------
    // resolve_quicksave(UGameEngine* engine_or_null) [stdcall ret 4]
    // arg1 == 0: returns 1 if CacheCoopQuickSave{Host|Client}.sav exists (> 0 B), else 0
    // arg1 != 0: populates [engine+0xE0] with that path and returns new len, or 0
    // -------------------------------------------------------------------------
    a.label("resolve_quicksave");
    // push ebx; push esi; push edi; sub esp, 0x820
    a.emit(&[0x53, 0x56, 0x57, 0x81, 0xEC, 0x20, 0x08, 0x00, 0x00]);
    // mov eax, ds:[PTR_SAVE_CFG_VA]
    a.u8(0xA1);
    a.u32(PTR_SAVE_CFG_VA);
    // test eax, eax; je fail
    a.emit(&[0x85, 0xC0]);
    a.jcc_rel32(0x84, "fail");
    // cmp dword ptr [eax+0x44], 1; jle fail
    a.emit(&[0x83, 0x78, 0x44, 0x01]);
    a.jcc_rel32(0x8E, "fail");
    // mov esi, dword ptr [eax+0x40] (save cache path prefix FString::Data)
    a.emit(&[0x8B, 0x70, 0x40]);
    // test esi, esi; je fail
    a.emit(&[0x85, 0xF6]);
    a.jcc_rel32(0x84, "fail");

    // Host vs Client selection via FN_IS_COOP_HOST
    a.call_external(FN_IS_COOP_HOST);
    // test eax, eax; jne use_host_fmt
    a.emit(&[0x85, 0xC0]);
    a.jcc_rel8(0x75, "use_host_fmt");
    // mov eax, fmt_client_va; jmp format_path
    a.u8(0xB8);
    a.u32(fmt_client_va);
    a.jmp_label("format_path");
    a.label("use_host_fmt");
    a.u8(0xB8);
    a.u32(fmt_host_va);

    a.label("format_path");
    // lea edi, [esp+0x10]; push esi; push eax; push edi; call appSnwprintf; add esp, 12
    a.emit(&[0x8D, 0x7C, 0x24, 0x10, 0x56, 0x50, 0x57]);
    a.call_external(FN_APP_SNWPRINTF_400);
    a.emit(&[0x83, 0xC4, 0x0C, 0x85, 0xC0]);
    a.jcc_rel32(0x8E, "fail");

    // GFileManager->FileSize(path_buf)
    a.emit(&[0x8B, 0x0D]);
    a.u32(PTR_FILE_MANAGER_VA);
    // test ecx, ecx; je fail; mov edx, [ecx]; push edi; call dword ptr [edx+0x10]
    a.emit(&[0x85, 0xC9]);
    a.jcc_rel32(0x84, "fail");
    a.emit(&[0x8B, 0x11, 0x57, 0xFF, 0x52, 0x10]);
    // test eax, eax; jle fail
    a.emit(&[0x85, 0xC0]);
    a.jcc_rel32(0x8E, "fail");

    // mov esi, dword ptr [esp+0x830] (arg1: UGameEngine* or null)
    a.emit(&[0x8B, 0xB4, 0x24, 0x30, 0x08, 0x00, 0x00]);
    // test esi, esi; jne populate_engine
    a.emit(&[0x85, 0xF6]);
    a.jcc_rel8(0x75, "populate_engine");
    // mov eax, 1; jmp done
    a.emit(&[0xB8, 0x01, 0x00, 0x00, 0x00]);
    a.jmp_label("done");

    a.label("populate_engine");
    // lea ecx, [esp]; push edi; call FString::FString(const TCHAR*)
    a.emit(&[0x8D, 0x0C, 0x24, 0x57]);
    a.call_external(FN_FSTRING_FROM_WSTR);
    // lea eax, [esp]; lea ecx, [esi+0xE0]; push eax; call FString::operator=
    a.emit(&[0x8D, 0x04, 0x24, 0x8D, 0x8E, 0xE0, 0x00, 0x00, 0x00, 0x50]);
    a.call_external(FN_FSTRING_ASSIGN);
    // lea ecx, [esp]; call FString::~FString
    a.emit(&[0x8D, 0x0C, 0x24]);
    a.call_external(FN_FSTRING_DTOR);
    // mov eax, dword ptr [esi+0xE4]; jmp done
    a.emit(&[0x8B, 0x86, 0xE4, 0x00, 0x00, 0x00]);
    a.jmp_label("done");

    a.label("fail");
    a.emit(&[0x33, 0xC0]);
    a.label("done");
    // add esp, 0x820; pop edi; pop esi; pop ebx; ret 4
    a.emit(&[0x81, 0xC4, 0x20, 0x08, 0x00, 0x00, 0x5F, 0x5E, 0x5B, 0xC2, 0x04, 0x00]);

    // -------------------------------------------------------------------------
    // Stub 1: MenuPause Quick Load check (0x10B28732)
    // -------------------------------------------------------------------------
    let stub_pause_va = a.cur_va();
    emit_menu_enable_stub(&mut a, "pause_resume", HOOK_PAUSE_QUICKLOAD_RESUME_VA);

    // -------------------------------------------------------------------------
    // Stub 2: MenuGameOver Quick Load check (0x10B29EB8)
    // -------------------------------------------------------------------------
    let stub_gameover_va = a.cur_va();
    emit_menu_enable_stub(&mut a, "gameover_resume", HOOK_GAMEOVER_QUICKLOAD_RESUME_VA);

    // -------------------------------------------------------------------------
    // Stub 3: CoopQuickLoad [UGameEngine+0xE4] fallback (0x10B23919)
    // -------------------------------------------------------------------------
    let stub_quickload_va = a.cur_va();
    // test eax, eax; je ql_zero
    a.emit(&[0x85, 0xC0]);
    a.jcc_rel8(0x74, "ql_zero");
    // mov ecx, dword ptr [eax+0xE4]; cmp ecx, 1; jg ql_have_len
    a.emit(&[0x8B, 0x88, 0xE4, 0x00, 0x00, 0x00, 0x83, 0xF9, 0x01]);
    a.jcc_rel8(0x7F, "ql_have_len");
    // push edx; push eax; call resolve_quicksave; pop edx; jmp resume
    a.emit(&[0x52, 0x50]);
    a.call_label("resolve_quicksave");
    a.u8(0x5A);
    a.jmp_external(HOOK_COOP_QUICKLOAD_LEN_RESUME_VA);

    a.label("ql_have_len");
    a.emit(&[0x89, 0xC8]);
    a.jmp_external(HOOK_COOP_QUICKLOAD_LEN_RESUME_VA);

    a.label("ql_zero");
    a.emit(&[0x33, 0xC0]);
    a.jmp_external(HOOK_COOP_QUICKLOAD_LEN_RESUME_VA);

    let code = a.finish();
    let mut page = vec![0u8; QUICKSAVE_ALLOC_SIZE];
    page[..code.len()].copy_from_slice(&code);

    let fmt_host = encode_utf16le_nul("%sCoopQuickSaveHost.sav");
    let fmt_client = encode_utf16le_nul("%sCoopQuickSaveClient.sav");
    assert!(fmt_host.len() <= (FMT_CLIENT_OFFSET - FMT_HOST_OFFSET) as usize);
    page[FMT_HOST_OFFSET as usize..FMT_HOST_OFFSET as usize + fmt_host.len()]
        .copy_from_slice(&fmt_host);
    page[FMT_CLIENT_OFFSET as usize..FMT_CLIENT_OFFSET as usize + fmt_client.len()]
        .copy_from_slice(&fmt_client);

    (
        page,
        QuickSaveHookOffsets {
            stub_pause_va,
            stub_gameover_va,
            stub_quickload_va,
        },
    )
}

/// Allocates and installs the persistent co-op Quick Load hooks into a suspended
/// `splintercell3.exe` process so restored `CacheCoopQuickSave*.sav` files can be loaded
/// immediately from Pause / Game Over after a restart.
#[cfg(windows)]
pub unsafe fn install_quicksave_persistence_hooks(
    h_process: windows_sys::Win32::Foundation::HANDLE,
    write_fn: unsafe fn(windows_sys::Win32::Foundation::HANDLE, usize, &[u8], bool),
) -> bool {
    use windows_sys::Win32::System::Diagnostics::Debug::{FlushInstructionCache, ReadProcessMemory};
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx,
    };

    unsafe {
        let alloc = VirtualAllocEx(
            h_process,
            std::ptr::null(),
            QUICKSAVE_ALLOC_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if alloc.is_null() {
            crate::scct_log!("  [QUICKSAVE] VirtualAllocEx failed; Quick Load persistence hook disabled");
            return false;
        }
        let base_va = alloc as usize;
        if base_va > u32::MAX as usize {
            crate::scct_log!(
                "  [QUICKSAVE] Allocation above 4GB (0x{:X}); Quick Load persistence hook disabled",
                base_va
            );
            return false;
        }

        let (page, offs) = build_quicksave_hook_page(base_va as u32);
        write_fn(h_process, base_va, &page, false);

        let hooks = [
            (
                HOOK_PAUSE_QUICKLOAD_VA,
                HOOK_PAUSE_QUICKLOAD_ORIG,
                offs.stub_pause_va,
                "MenuPause::QuickLoad",
            ),
            (
                HOOK_GAMEOVER_QUICKLOAD_VA,
                HOOK_GAMEOVER_QUICKLOAD_ORIG,
                offs.stub_gameover_va,
                "MenuGameOver::QuickLoad",
            ),
            (
                HOOK_COOP_QUICKLOAD_LEN_VA,
                HOOK_COOP_QUICKLOAD_LEN_ORIG,
                offs.stub_quickload_va,
                "CoopQuickLoad::Filename",
            ),
        ];

        let mut installed = 0usize;
        for (va, orig, stub_va, label) in hooks {
            let mut cur = [0u8; 6];
            let mut nread = 0usize;
            let ok = ReadProcessMemory(
                h_process,
                va as *const _,
                cur.as_mut_ptr() as *mut _,
                orig.len(),
                &mut nread,
            );
            if ok == 0 || nread != orig.len() || cur != orig {
                crate::scct_log!(
                    "  [QUICKSAVE] Skipping hook {} @ 0x{:08X} (bytes mismatch: {:02X?})",
                    label,
                    va,
                    cur
                );
                continue;
            }
            let jmp = crate::net::make_jmp(va, stub_va, orig.len());
            write_fn(h_process, va as usize, &jmp, true);
            installed += 1;
        }

        let _ = FlushInstructionCache(h_process, std::ptr::null(), 0);
        crate::scct_log!(
            "  [QUICKSAVE] Installed {}/{} Quick Load persistence hooks (@ 0x{:08X})",
            installed,
            hooks.len(),
            base_va
        );
        installed == hooks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FMT_CLIENT_OFFSET, FMT_HOST_OFFSET, PersistentQuickSaveHandle,
        build_quicksave_hook_page, prune_old_backups, restore_quick_saves_from_dirs_with_delay,
        snapshot_quick_saves_with_delay, spawn_quicksave_persistence,
    };
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn make_temp_dir(label: &str) -> PathBuf {
        let unique_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "scct-quicksave-{label}-{}-{unique_id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn prunes_timestamped_backups_to_the_newest_three() {
        let backup_dir = make_temp_dir("retention");

        for index in 1..=5 {
            std::fs::write(
                backup_dir.join(format!("host_{index:020}.sav")),
                index.to_string(),
            )
            .unwrap();
        }
        std::fs::write(backup_dir.join("host_latest.sav"), "latest").unwrap();

        prune_old_backups(&backup_dir, "host").unwrap();

        let mut retained = std::fs::read_dir(&backup_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        retained.sort();
        let mut expected = (3..=5)
            .map(|index| format!("host_{index:020}.sav"))
            .collect::<Vec<_>>();
        expected.push("host_latest.sav".to_string());
        expected.sort();
        assert_eq!(retained, expected);

        std::fs::remove_dir_all(backup_dir).unwrap();
    }

    #[test]
    fn restore_preserves_newer_live_save_instead_of_clobbering_it() {
        let root = make_temp_dir("no-clobber");
        let profile = root.join("profile");
        let backup = root.join("backup");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::create_dir_all(&backup).unwrap();

        let live_host = profile.join("CacheCoopQuickSaveHost.sav");
        let backup_host = backup.join("host_latest.sav");

        // Write older backup first, wait slightly so FS timestamp advances, then write newer live save.
        std::fs::write(&backup_host, b"OLD_BACKUP").unwrap();
        std::thread::sleep(Duration::from_millis(30));
        std::fs::write(&live_host, b"NEW_LIVE_SAVE").unwrap();

        let (backed_up, restored) =
            restore_quick_saves_from_dirs_with_delay(&profile, &backup, Duration::from_millis(5))
                .unwrap();

        assert_eq!(backed_up, 1);
        assert_eq!(restored, 0);
        assert_eq!(std::fs::read(&live_host).unwrap(), b"NEW_LIVE_SAVE");
        assert_eq!(std::fs::read(&backup_host).unwrap(), b"NEW_LIVE_SAVE");

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restore_recovers_missing_live_save_from_backup() {
        let root = make_temp_dir("recover");
        let profile = root.join("profile");
        let backup = root.join("backup");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::create_dir_all(&backup).unwrap();

        std::fs::write(backup.join("client_latest.sav"), b"CLIENT_SAVE").unwrap();

        let (backed_up, restored) =
            restore_quick_saves_from_dirs_with_delay(&profile, &backup, Duration::from_millis(5))
                .unwrap();

        assert_eq!(backed_up, 0);
        assert_eq!(restored, 1);
        assert_eq!(
            std::fs::read(profile.join("CacheCoopQuickSaveClient.sav")).unwrap(),
            b"CLIENT_SAVE"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn snapshot_skips_actively_changing_file_until_settled() {
        let root = make_temp_dir("settle");
        let profile = root.join("profile");
        let backup = root.join("backup");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::create_dir_all(&backup).unwrap();

        let live_host = profile.join("CacheCoopQuickSaveHost.sav");
        std::fs::write(&live_host, vec![1u8; 64]).unwrap();

        // Writer keeps appending across checks for ~180ms, then finishes at 256 bytes.
        let writer_path = live_host.clone();
        let writer = std::thread::spawn(move || {
            for step in 2..=4 {
                std::thread::sleep(Duration::from_millis(45));
                std::fs::write(&writer_path, vec![step as u8; step * 64]).unwrap();
            }
        });

        let count = snapshot_quick_saves_with_delay(
            &profile,
            &backup,
            Duration::from_millis(80),
            false,
        )
        .unwrap();
        writer.join().unwrap();

        assert_eq!(count, 1);
        assert_eq!(std::fs::read(backup.join("host_latest.sav")).unwrap(), vec![4u8; 256]);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_snapshot_does_not_clobber_newer_backup_with_older_live_save() {
        let root = make_temp_dir("keep-newer-backup");
        let profile = root.join("profile");
        let backup = root.join("backup");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::create_dir_all(&backup).unwrap();

        let live_host = profile.join("CacheCoopQuickSaveHost.sav");
        let backup_host = backup.join("host_latest.sav");

        std::fs::write(&live_host, b"OLD_LIVE").unwrap();
        std::thread::sleep(Duration::from_millis(30));
        std::fs::write(&backup_host, b"NEWER_BACKUP").unwrap();

        let count = snapshot_quick_saves_with_delay(
            &profile,
            &backup,
            Duration::from_millis(5),
            true,
        )
        .unwrap();

        assert_eq!(count, 0);
        assert_eq!(std::fs::read(&backup_host).unwrap(), b"NEWER_BACKUP");

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn worker_tracks_game_root_and_flushes_before_stop() {
        let root = make_temp_dir("worker");
        let handle: PersistentQuickSaveHandle = spawn_quicksave_persistence(root.clone());
        assert_eq!(handle.game_root(), root.as_path());
        drop(handle);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn quicksave_hook_page_disassembles_cleanly() {
        let base_va = 0x2000_0000;
        let (page, offs) = build_quicksave_hook_page(base_va);
        assert!(offs.stub_pause_va >= base_va);
        assert!(offs.stub_gameover_va > offs.stub_pause_va);
        assert!(offs.stub_quickload_va > offs.stub_gameover_va);

        let decode_utf16z = |slice: &[u8]| {
            let end = slice
                .as_chunks::<2>()
                .0
                .iter()
                .position(|&c| c == [0, 0])
                .unwrap()
                * 2;
            String::from_utf16(
                &slice[..end]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .copied()
                    .map(u16::from_le_bytes)
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        };
        assert_eq!(
            decode_utf16z(&page[FMT_HOST_OFFSET as usize..FMT_CLIENT_OFFSET as usize]),
            "%sCoopQuickSaveHost.sav"
        );
        assert_eq!(
            decode_utf16z(&page[FMT_CLIENT_OFFSET as usize..FMT_CLIENT_OFFSET as usize + 64]),
            "%sCoopQuickSaveClient.sav"
        );

        let bin_path = make_temp_dir("objdump").join("page.bin");
        let code_len = (offs.stub_quickload_va - base_va) as usize + 42;
        std::fs::write(&bin_path, &page[..code_len]).unwrap();
        if let Ok(output) = Command::new("objdump")
            .args([
                "-D",
                "-b",
                "binary",
                "-m",
                "i386",
                "-M",
                "intel",
                &format!("--adjust-vma=0x{base_va:x}"),
                bin_path.to_str().unwrap(),
            ])
            .output()
            && output.status.success()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(
                !text.contains("(bad)"),
                "Invalid x86 encoding in quicksave hook page:\n{}",
                text
            );
            for expected in [
                "0x1095b880",
                "0x10ccb0d0",
                "0x1090ba00",
                "0x109097e0",
                "0x1090ba70",
                "0x10b28738",
                "0x10b29ebe",
                "0x10b2391f",
            ] {
                assert!(
                    text.contains(expected),
                    "Missing target {} in quicksave hook disassembly:\n{}",
                    expected,
                    text
                );
            }
        }
        let _ = std::fs::remove_dir_all(bin_path.parent().unwrap());

        let p1 = std::path::Path::new(
            "../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe",
        );
        let p2 = std::path::Path::new(
            "../../clean_scct_files/Tom Clancy's Splinter Cell Chaos Theory/System/splintercell3.exe",
        );
        let clean_exe = if p1.exists() {
            Some(p1)
        } else if p2.exists() {
            Some(p2)
        } else {
            None
        };
        if let Some(clean_exe_path) = clean_exe {
            let exe = std::fs::read(clean_exe_path).unwrap();
            for (va, orig) in [
                (super::HOOK_PAUSE_QUICKLOAD_VA, super::HOOK_PAUSE_QUICKLOAD_ORIG),
                (
                    super::HOOK_GAMEOVER_QUICKLOAD_VA,
                    super::HOOK_GAMEOVER_QUICKLOAD_ORIG,
                ),
                (
                    super::HOOK_COOP_QUICKLOAD_LEN_VA,
                    super::HOOK_COOP_QUICKLOAD_LEN_ORIG,
                ),
            ] {
                let off = (va - 0x1090_0000) as usize;
                assert_eq!(&exe[off..off + orig.len()], &orig);
            }
        }
    }
}
