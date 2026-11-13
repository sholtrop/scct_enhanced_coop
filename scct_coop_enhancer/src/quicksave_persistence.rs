use anyhow::{Context, Result};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Sender, channel};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct PersistentQuickSaveHandle {
    stop_tx: Sender<()>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl std::fmt::Debug for PersistentQuickSaveHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistentQuickSaveHandle")
            .finish_non_exhaustive()
    }
}

impl PersistentQuickSaveHandle {
    pub fn stop(&mut self) {
        let _ = self.stop_tx.send(());
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
            let has_save_files = [
                candidate.join("CacheCoopQuickSaveHost.sav"),
                candidate.join("CacheCoopQuickSaveClient.sav"),
            ]
            .iter()
            .any(|p| p.exists());
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

fn snapshot_quick_saves(profile_dir: &Path, backup_dir: &Path) -> Result<()> {
    let save_names = [
        ("CacheCoopQuickSaveHost.sav", "host"),
        ("CacheCoopQuickSaveClient.sav", "client"),
    ];

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    for (source_name, prefix) in save_names {
        let source = profile_dir.join(source_name);
        let latest = backup_dir.join(format!("{prefix}_latest.sav"));
        if source.exists() {
            let contents = std::fs::read(&source)
                .with_context(|| format!("Reading quick save {}", source.display()))?;
            let latest_contents = std::fs::read(&latest).ok();
            if latest_contents.as_deref() != Some(contents.as_slice()) {
                let stamped = backup_dir.join(format!("{prefix}_{ts}.sav"));
                std::fs::write(&stamped, &contents)
                    .with_context(|| format!("Writing backup {}", stamped.display()))?;
                std::fs::write(&latest, &contents)
                    .with_context(|| format!("Updating latest backup {}", latest.display()))?;
            }
        }
        prune_old_backups(backup_dir, prefix)?;
    }

    Ok(())
}

pub fn snapshot_quick_saves_for_persistence(game_root: &Path) -> Result<()> {
    let profile_dir = find_scct_quicksave_profile_dir(game_root)
        .context("Could not locate the SCCT quick-save profile directory")?;
    let backup_dir = ensure_quick_save_backup_dir(game_root);
    snapshot_quick_saves(&profile_dir, &backup_dir)
}

fn restore_quick_saves_from_dirs(profile_dir: &Path, backup_dir: &Path) -> Result<()> {
    let restore_pairs = [
        ("host_latest.sav", "CacheCoopQuickSaveHost.sav"),
        ("client_latest.sav", "CacheCoopQuickSaveClient.sav"),
    ];

    for (latest_name, target_name) in restore_pairs {
        let latest = backup_dir.join(latest_name);
        let target = profile_dir.join(target_name);
        if latest.exists() {
            std::fs::copy(&latest, &target).with_context(|| {
                format!("Restoring {} to {}", latest.display(), target.display())
            })?;
        }
    }

    Ok(())
}

pub fn restore_latest_quick_saves(game_root: &Path) -> Result<()> {
    let profile_dir = find_scct_quicksave_profile_dir(game_root)
        .context("Could not locate the SCCT quick-save profile directory")?;
    let backup_dir = ensure_quick_save_backup_dir(game_root);
    restore_quick_saves_from_dirs(&profile_dir, &backup_dir)
}

fn is_save_event(event: &Event) -> bool {
    let files: Vec<_> = event
        .paths
        .iter()
        .map(|p| p.file_name().unwrap_or_default())
        .collect();
    files.iter().any(|name| {
        let name = name.to_string_lossy();
        name == "CacheCoopQuickSaveHost.sav" || name == "CacheCoopQuickSaveClient.sav"
    })
}

pub fn spawn_quicksave_persistence(game_root: PathBuf) -> PersistentQuickSaveHandle {
    let (stop_tx, stop_rx) = channel();
    let join_handle = thread::spawn(move || {
        let _ = restore_latest_quick_saves(&game_root);

        let profile_dir = match find_scct_quicksave_profile_dir(&game_root) {
            Some(dir) => dir,
            None => {
                let _ = stop_rx.recv_timeout(Duration::from_secs(1));
                return;
            }
        };

        let (event_tx, event_rx) = channel::<()>();
        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res
                    && matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Access(_)
                    ) && is_save_event(&event)
                {
                    let _ = event_tx.send(());
                }
            },
            Config::default(),
        )
        .unwrap_or_else(|_| RecommendedWatcher::new(|_| {}, Config::default()).unwrap());

        let _ = watcher.watch(&profile_dir, RecursiveMode::NonRecursive);
        let mut last_snapshot = SystemTime::now();

        loop {
            if let Ok(()) = stop_rx.try_recv() {
                break;
            }

            if let Ok(()) = event_rx.recv_timeout(Duration::from_millis(100)) {
                let _ = snapshot_quick_saves_for_persistence(&game_root);
                last_snapshot = SystemTime::now();
                continue;
            }

            if last_snapshot.elapsed().unwrap_or(Duration::from_secs(0)) >= Duration::from_secs(5) {
                let _ = snapshot_quick_saves_for_persistence(&game_root);
                last_snapshot = SystemTime::now();
            }
        }
    });

    PersistentQuickSaveHandle {
        stop_tx,
        join_handle: Some(join_handle),
    }
}

#[cfg(test)]
mod tests {
    use super::prune_old_backups;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn prunes_timestamped_backups_to_the_newest_three() {
        let unique_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let backup_dir = std::env::temp_dir().join(format!(
            "scct-quicksave-retention-{}-{unique_id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&backup_dir).unwrap();

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
}
