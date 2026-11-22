use crate::quicksave_persistence::PersistentQuickSaveHandle;
use eframe::egui::{self, Color32, RichText, ScrollArea, Vec2};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NucleusNetModeChoice {
    PreserveNucleusLan,
    BuiltInLoopbackPair,
    ExplicitPair,
}

impl NucleusNetModeChoice {
    fn label(self) -> &'static str {
        match self {
            NucleusNetModeChoice::BuiltInLoopbackPair => {
                "Built-in Loopback Pair (127.0.0.2 <-> 127.0.0.3) — Recommended"
            }
            NucleusNetModeChoice::ExplicitPair => "Custom Adapter IP Pair",
            NucleusNetModeChoice::PreserveNucleusLan => {
                "Respect Nucleus Network (ForceBindIP / Loopback Adapters only)"
            }
        }
    }
}

pub struct NucleusWatcherHandle {
    stop_tx: Sender<()>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl std::fmt::Debug for NucleusWatcherHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NucleusWatcherHandle")
            .finish_non_exhaustive()
    }
}

impl NucleusWatcherHandle {
    pub fn stop(&mut self) {
        let _ = self.stop_tx.send(());
        if let Some(h) = self.join_handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for NucleusWatcherHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Debug, PartialEq, Eq)]
enum InstallState {
    Idle,
    Installing,
    Uninstalling,
    Failed,
}

fn install_button_label(state: &InstallState) -> &'static str {
    match state {
        InstallState::Idle => "🎮 Install Mod",
        InstallState::Installing => "Installing Mod... (Please wait)",
        InstallState::Uninstalling => "Uninstalling Mod... (Please wait)",
        InstallState::Failed => "❌ Installation Failed (Click to Retry)",
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeepaliveCommand {
    Stop,
    Disconnect,
}

pub struct KeepaliveHandle {
    cmd_tx: Sender<KeepaliveCommand>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl std::fmt::Debug for KeepaliveHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeepaliveHandle").finish_non_exhaustive()
    }
}

impl KeepaliveHandle {
    pub fn stop_and_wait(&mut self) {
        let _ = self.cmd_tx.send(KeepaliveCommand::Stop);
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }

    pub fn disconnect_and_wait(&mut self) {
        let _ = self.cmd_tx.send(KeepaliveCommand::Disconnect);
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for KeepaliveHandle {
    fn drop(&mut self) {
        self.disconnect_and_wait();
    }
}

pub struct SessionMonitorHandle {
    stop_tx: Sender<()>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl std::fmt::Debug for SessionMonitorHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionMonitorHandle")
            .finish_non_exhaustive()
    }
}

impl SessionMonitorHandle {
    pub fn stop(&mut self) {
        let _ = self.stop_tx.send(());
        if let Some(h) = self.join_handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for SessionMonitorHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

fn spawn_session_monitor(
    server_host: String,
    api_port: u16,
    code: String,
    role: String,
    tx: Sender<GuiEvent>,
    ctx: egui::Context,
) -> SessionMonitorHandle {
    let (stop_tx, stop_rx) = channel();
    let join_handle = thread::spawn(move || {
        loop {
            match stop_rx.recv_timeout(Duration::from_millis(2000)) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    match crate::stun::poll_server_for_peer(
                        &server_host,
                        api_port,
                        &code,
                        Some(&role),
                    ) {
                        Ok(crate::stun::PollPeerResult::Disconnected(reason)) => {
                            let _ = tx.send(GuiEvent::PeerDisconnected(format!(
                                "Friend disconnected ({})",
                                reason
                            )));
                            ctx.request_repaint();
                            break;
                        }
                        Ok(crate::stun::PollPeerResult::Paired(..)) => {}
                        Ok(crate::stun::PollPeerResult::Waiting) => {}
                        Err(e) => {
                            let err_msg = format!("{:#}", e);
                            if err_msg.contains("code_not_found")
                                || err_msg.contains("expired or not found")
                                || err_msg.contains("404")
                            {
                                let _ = tx.send(GuiEvent::PeerDisconnected(
                                    "Friend disconnected (session ended).".to_string(),
                                ));
                                ctx.request_repaint();
                                break;
                            }
                        }
                    }
                }
            }
        }
    });
    SessionMonitorHandle {
        stop_tx,
        join_handle: Some(join_handle),
    }
}

fn spawn_punch_keepalive(
    sock_disco: std::net::UdpSocket,
    sock_game: std::net::UdpSocket,
    peer_disco: std::net::SocketAddr,
    peer_game: std::net::SocketAddr,
    tx: Sender<GuiEvent>,
    ctx: egui::Context,
) -> KeepaliveHandle {
    let (cmd_tx, cmd_rx) = channel();
    let join_handle = thread::spawn(move || {
        let _ = sock_disco.set_nonblocking(true);
        let _ = sock_game.set_nonblocking(true);
        let mut buf = [0u8; 512];

        loop {
            // 1. Drain and handle incoming packets on discovery socket
            loop {
                match sock_disco.recv_from(&mut buf) {
                    Ok((len, src)) => {
                        let data = &buf[..len];
                        if data.starts_with(crate::stun::SCCT_DISCONNECT_PAYLOAD) {
                            let _ = tx.send(GuiEvent::PeerDisconnected(
                                "Friend disconnected from session.".to_string(),
                            ));
                            ctx.request_repaint();
                            return;
                        } else if data.starts_with(crate::stun::SCCT_PING_PAYLOAD) {
                            let _ = sock_disco.send_to(crate::stun::SCCT_PONG_PAYLOAD, src);
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                    Err(_) => break,
                }
            }

            // 2. Drain and handle incoming packets on gameplay socket
            loop {
                match sock_game.recv_from(&mut buf) {
                    Ok((len, src)) => {
                        let data = &buf[..len];
                        if data.starts_with(crate::stun::SCCT_DISCONNECT_PAYLOAD) {
                            let _ = tx.send(GuiEvent::PeerDisconnected(
                                "Friend disconnected from session.".to_string(),
                            ));
                            ctx.request_repaint();
                            return;
                        } else if data.starts_with(crate::stun::SCCT_PING_PAYLOAD) {
                            let _ = sock_game.send_to(crate::stun::SCCT_PONG_PAYLOAD, src);
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(ref e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                    Err(_) => break,
                }
            }

            // 3. Check for stop/disconnect commands with timeout
            match cmd_rx.recv_timeout(Duration::from_millis(1000)) {
                Ok(KeepaliveCommand::Disconnect) => {
                    crate::stun::send_udp_disconnect(
                        &sock_disco,
                        &sock_game,
                        peer_disco,
                        peer_game,
                    );
                    break;
                }
                Ok(KeepaliveCommand::Stop) => {
                    // Silent stop (e.g. launching game)
                    break;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    crate::stun::send_udp_disconnect(
                        &sock_disco,
                        &sock_game,
                        peer_disco,
                        peer_game,
                    );
                    break;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // Send ping + punch packets to keep NAT mappings refreshed
                    let _ = sock_disco.send_to(crate::stun::SCCT_PING_PAYLOAD, peer_disco);
                    let _ = sock_game.send_to(crate::stun::SCCT_PING_PAYLOAD, peer_game);
                    let _ = sock_disco.send_to(crate::stun::SCCT_PUNCH_PAYLOAD, peer_disco);
                    let _ = sock_game.send_to(crate::stun::SCCT_PUNCH_PAYLOAD, peer_game);
                }
            }
        }
    });
    KeepaliveHandle {
        cmd_tx,
        join_handle: Some(join_handle),
    }
}

#[derive(Debug)]
pub enum MatchState {
    Idle,
    Hosting {
        code: String,
        status_text: String,
    },
    Joining {
        target_code: String,
        status_text: String,
    },
    Matched {
        code: String,
        is_host: bool,
        peer_ip: Ipv4Addr,
        peer_disco_port: u16,
        peer_game_port: u16,
        game_launched: bool,
    },
    Failed {
        error: String,
    },
}

pub enum GuiEvent {
    Log(String),
    InstallDone {
        root: PathBuf,
        ok: bool,
    },
    UninstallDone {
        root: PathBuf,
        ok: bool,
    },
    FlagsApplyDone {
        ok: bool,
        applied: Option<crate::patcher::ModFlags>,
    },
    FriendCodeRegistered(String),
    MatchStatus(String),
    Matched {
        code: String,
        is_host: bool,
        peer_ip: Ipv4Addr,
        peer_disco_port: u16,
        peer_game_port: u16,
        keepalive: Option<KeepaliveHandle>,
    },
    MatchFailed(String),
    PeerDisconnected(String),
    GameAttached(u32),
    GameExited(u32),
    DesyncDetected(crate::launcher::DesyncReport),
    DesyncDumpFailed(String),
}

pub struct PatcherApp {
    game_dir_input: String,
    resolved_root: Option<PathBuf>,
    detected_roots: Vec<PathBuf>,
    detection_msg: String,
    installed_version: Option<String>,
    state: InstallState,
    log_lines: Vec<String>,
    receiver: Receiver<GuiEvent>,
    sender: Sender<GuiEvent>,

    // Running / attached game processes (supports multiple simultaneous Nucleus Co-op instances)
    active_game_pids: Arc<Mutex<HashSet<u32>>>,

    // Nucleus Co-op / External Attach Mode
    nucleus_net_mode: NucleusNetModeChoice,
    nucleus_pair_ip1: String,
    nucleus_pair_ip2: String,
    nucleus_watcher: Option<NucleusWatcherHandle>,
    nucleus_next_slot: usize,

    // Friend Code Matchmaking
    match_state: MatchState,
    guest_code_input: String,
    cancel_tx: Option<Sender<()>>,
    keepalive: Option<KeepaliveHandle>,
    session_monitor: Option<SessionMonitorHandle>,
    persistent_quick_saves: Option<PersistentQuickSaveHandle>,
    disconnect_notice: Option<String>,

    // Advanced Server Settings
    server_host: String,
    stun_port: u16,
    api_port: u16,

    // Multi-NIC adapter binding (None = Auto / All Adapters)
    available_local_ips: Vec<std::net::Ipv4Addr>,
    selected_bind_ip: Option<std::net::Ipv4Addr>,

    // Stage 1 instant Host -> Client resync on checksum mismatch
    auto_resync: bool,

    // Show debug/mod flag UI controls only when `--dev` is passed at startup
    dev_mode: bool,

    // Per-feature patch toggles across all 6 mod groups (28 toggles)
    patch_flags: crate::patcher::ModFlags,
    applied_flags: Option<crate::patcher::ModFlags>,
    applying_flags: bool,
}

impl PatcherApp {
    pub fn new(
        cc: &eframe::CreationContext,
        explicit_dir: Option<PathBuf>,
        initial_bind_ip: Option<std::net::Ipv4Addr>,
        initial_auto_resync: bool,
        dev_mode: bool,
    ) -> Self {
        // Force dark mode regardless of OS light/dark theme preference
        let mut dark_visuals = egui::Visuals::dark();
        dark_visuals.panel_fill = Color32::from_rgb(18, 20, 24);
        cc.egui_ctx.set_theme(egui::ThemePreference::Dark);
        cc.egui_ctx
            .set_visuals_of(egui::Theme::Dark, dark_visuals.clone());
        cc.egui_ctx
            .set_visuals_of(egui::Theme::Light, dark_visuals.clone());
        cc.egui_ctx.set_visuals(dark_visuals);

        Self::init_state(explicit_dir, initial_bind_ip, initial_auto_resync, dev_mode, true)
    }

    fn init_state(
        explicit_dir: Option<PathBuf>,
        initial_bind_ip: Option<std::net::Ipv4Addr>,
        initial_auto_resync: bool,
        dev_mode: bool,
        auto_detect: bool,
    ) -> Self {
        let (sender, receiver) = channel();
        let initial_bind_ip = initial_bind_ip.filter(|ip| !ip.is_unspecified());

        let available_local_ips = crate::ip::get_all_local_ips();
        let default_ip1 = available_local_ips
            .first()
            .map(ToString::to_string)
            .unwrap_or_else(|| "127.0.0.2".to_string());
        let default_ip2 = available_local_ips
            .get(1)
            .map(ToString::to_string)
            .unwrap_or_else(|| "127.0.0.3".to_string());

        let mut app = Self {
            game_dir_input: String::new(),
            resolved_root: None,
            detected_roots: Vec::new(),
            detection_msg: String::new(),
            installed_version: None,
            state: InstallState::Idle,
            log_lines: Vec::new(),
            receiver,
            sender,
            active_game_pids: Arc::new(Mutex::new(HashSet::new())),
            nucleus_net_mode: NucleusNetModeChoice::BuiltInLoopbackPair,
            nucleus_pair_ip1: default_ip1,
            nucleus_pair_ip2: default_ip2,
            nucleus_watcher: None,
            nucleus_next_slot: 0,
            match_state: MatchState::Idle,
            guest_code_input: String::new(),
            cancel_tx: None,
            keepalive: None,
            session_monitor: None,
            persistent_quick_saves: None,
            disconnect_notice: None,
            server_host: crate::stun::DEFAULT_SERVER_HOST.to_string(),
            stun_port: crate::stun::DEFAULT_STUN_PORT,
            api_port: crate::stun::DEFAULT_API_PORT,
            available_local_ips,
            selected_bind_ip: initial_bind_ip,
            auto_resync: initial_auto_resync,
            dev_mode,
            patch_flags: crate::patcher::ModFlags::default(),
            applied_flags: None,
            applying_flags: false,
        };

        let detected = if auto_detect {
            crate::patcher::auto_detect_game_roots()
        } else {
            Vec::new()
        };
        app.detected_roots = detected.clone();

        if let Some(explicit) = explicit_dir {
            if let Some(valid) = crate::patcher::validate_game_root(&explicit) {
                app.set_game_root(valid);
            } else {
                app.game_dir_input = explicit.display().to_string();
                app.detection_msg = format!(
                    "System/splintercell3.exe not found in specified folder: {}",
                    explicit.display()
                );
            }
        } else if detected.len() == 1 {
            app.set_game_root(detected[0].clone());
        } else if detected.len() > 1 {
            app.set_game_root(detected[0].clone());
            app.detection_msg = format!(
                "Auto-detected {} game installations. Selected: {}",
                detected.len(),
                detected[0].display()
            );
        } else {
            app.detection_msg =
                "Splinter Cell Chaos Theory not detected. Please browse to your game folder."
                    .to_string();
        }

        app
    }

    pub fn set_game_root(&mut self, root: PathBuf) {
        self.game_dir_input = root.display().to_string();
        self.state = InstallState::Idle;
        self.installed_version = crate::patcher::get_installed_version(&root);

        if let Some(ref ver) = self.installed_version {
            self.detection_msg = format!(
                "Game detected: {} (Co-op Mod v{} installed)",
                root.display(),
                ver
            );
        } else {
            self.detection_msg = format!("Game detected: {} (Vanilla)", root.display());
        }
        self.resolved_root = Some(root.clone());
        self.update_flags_from_disk(&root, None, true);
        self.sync_quicksave_worker();
    }

    fn clear_game_root(&mut self, msg: String) {
        self.resolved_root = None;
        self.installed_version = None;
        self.applied_flags = None;
        self.state = InstallState::Idle;
        self.detection_msg = msg;
        self.stop_persistent_quick_saves();
    }

    /// Updates install state after `apply_all_with_flags` finishes for `event_root`.
    fn handle_install_done(&mut self, event_root: &Path, ok: bool) {
        if self.resolved_root.as_deref() != Some(event_root) {
            if matches!(self.state, InstallState::Installing) {
                self.state = InstallState::Idle;
            }
            return;
        }
        if ok {
            self.installed_version = crate::patcher::get_installed_version(event_root);
            if let Some(ver) = self.installed_version.clone() {
                self.state = InstallState::Idle;
                let fallback = self.patch_flags;
                self.update_flags_from_disk(event_root, Some(fallback), false);
                self.detection_msg =
                    format!("Game detected: {} (Co-op Mod v{} installed)", event_root.display(), ver);
                self.sync_quicksave_worker();
            } else {
                self.state = InstallState::Failed;
            }
        } else {
            self.state = InstallState::Failed;
        }
    }

    /// Updates install state after `restore_vanilla` finishes for `event_root`.
    fn handle_uninstall_done(&mut self, event_root: &Path, ok: bool) {
        if self.resolved_root.as_deref() != Some(event_root) {
            if matches!(self.state, InstallState::Uninstalling) {
                self.state = InstallState::Idle;
            }
            return;
        }
        self.state = InstallState::Idle;
        if ok {
            self.installed_version = crate::patcher::get_installed_version(event_root);
            self.applied_flags = None;
            self.detection_msg = format!("Game detected: {} (Vanilla)", event_root.display());
        }
    }

    fn start_install_task(&mut self, ctx: &egui::Context, completion_msg: &'static str) {
        let Some(root) = self.resolved_root.clone() else {
            return;
        };
        self.state = InstallState::Installing;
        self.log_lines.clear();

        let tx = self.sender.clone();
        let tx_status = self.sender.clone();
        let ctx_clone = ctx.clone();
        let patch_flags = self.patch_flags;

        crate::patcher::set_log_sink(move |msg| {
            let _ = tx.send(GuiEvent::Log(msg.to_string()));
            ctx_clone.request_repaint();
        });

        let ctx_finish = ctx.clone();
        thread::spawn(move || {
            let res = crate::patcher::apply_all_with_flags(&root, &patch_flags);
            match res {
                Ok(_) => {
                    let _ = tx_status.send(GuiEvent::Log(completion_msg.to_string()));
                    let _ = tx_status.send(GuiEvent::InstallDone { root, ok: true });
                }
                Err(e) => {
                    let _ = tx_status.send(GuiEvent::Log(format!("\n>>> ERROR: {:#}", e)));
                    let _ = tx_status.send(GuiEvent::InstallDone { root, ok: false });
                }
            }
            crate::patcher::clear_log_sink();
            ctx_finish.request_repaint();
        });
    }

    /// Refreshes `applied_flags` from disk; in non-dev mode, keeps `patch_flags` pinned to the default preset.
    fn update_flags_from_disk(
        &mut self,
        root: &Path,
        fallback_applied: Option<crate::patcher::ModFlags>,
        reset_to_default_if_undetected: bool,
    ) {
        let detected = crate::patcher::ModFlags::detect_from_disk(root, Some(&self.patch_flags));
        if self.dev_mode {
            if let Some(d) = detected {
                self.patch_flags = d;
            } else if reset_to_default_if_undetected {
                self.patch_flags = crate::patcher::ModFlags::default();
            }
        } else {
            self.patch_flags = crate::patcher::ModFlags::default();
        }
        self.applied_flags = detected.or(fallback_applied);
    }

    fn sync_quicksave_worker(&mut self) {
        if self.patch_flags.runtime_quicksave_persistence {
            if let Some(root) = self.resolved_root.clone() {
                let needs_restart = self
                    .persistent_quick_saves
                    .as_ref()
                    .is_some_and(|handle| handle.game_root() != root.as_path());
                if needs_restart {
                    self.stop_persistent_quick_saves();
                }
                if self.persistent_quick_saves.is_none() {
                    self.persistent_quick_saves = Some(
                        crate::quicksave_persistence::spawn_quicksave_persistence(root),
                    );
                }
            }
        } else {
            self.stop_persistent_quick_saves();
        }
    }

    fn check_manual_path_input(&mut self) {
        let trimmed = self.game_dir_input.trim();
        if trimmed.is_empty() {
            self.clear_game_root("Please select or enter the Chaos Theory game folder.".to_string());
            return;
        }

        let path = Path::new(trimmed);
        if let Some(valid) = crate::patcher::validate_game_root(path) {
            if self.resolved_root.as_ref() != Some(&valid) {
                self.set_game_root(valid);
            }
        } else {
            self.clear_game_root(
                "System/splintercell3.exe not found in this folder. Please verify the path."
                    .to_string(),
            );
        }
    }

    fn stop_keepalive(&mut self) {
        if let Some(mut ka) = self.keepalive.take() {
            ka.stop_and_wait();
        }
    }

    fn disconnect_keepalive(&mut self) {
        if let Some(mut ka) = self.keepalive.take() {
            ka.disconnect_and_wait();
        }
    }

    fn stop_session_monitor(&mut self) {
        if let Some(mut mon) = self.session_monitor.take() {
            mon.stop();
        }
    }

    fn stop_nucleus_watcher(&mut self) {
        if let Some(mut watcher) = self.nucleus_watcher.take() {
            watcher.stop();
        }
    }

    fn active_pids_sorted(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = self
            .active_game_pids
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .copied()
            .collect();
        pids.sort_unstable();
        pids
    }

    fn selected_nucleus_net_mode(&self) -> anyhow::Result<crate::launcher::NucleusNetMode> {
        match self.nucleus_net_mode {
            NucleusNetModeChoice::PreserveNucleusLan => {
                Ok(crate::launcher::NucleusNetMode::PreserveNucleusLan)
            }
            NucleusNetModeChoice::BuiltInLoopbackPair => {
                Ok(crate::launcher::NucleusNetMode::BuiltInLoopbackPair)
            }
            NucleusNetModeChoice::ExplicitPair => {
                let raw = format!(
                    "{},{}",
                    self.nucleus_pair_ip1.trim(),
                    self.nucleus_pair_ip2.trim()
                );
                let (ip1, ip2) = crate::launcher::parse_ip_pair(&raw)?;
                Ok(crate::launcher::NucleusNetMode::ExplicitPair(ip1, ip2))
            }
        }
    }

    fn build_launch_runtime_options(&self) -> crate::launcher::LaunchRuntimeOptions {
        crate::launcher::LaunchRuntimeOptions {
            auto_resync: self.auto_resync,
            install_trace_hooks: self.patch_flags.runtime_startup_trace_hooks,
            monitor_desync_dump: self.patch_flags.runtime_desync_monitor_dump,
            inject_lan_net_globals: self.patch_flags.net_multi_nic_adapter_fix,
            inject_nat_direct_target: self.patch_flags.net_nat_and_direct_ip,
            enable_persistent_quicksave_load: self.patch_flags.runtime_quicksave_persistence,
        }
    }

    fn flush_quicksaves_on_game_exit(&mut self) {
        if !self.patch_flags.runtime_quicksave_persistence {
            return;
        }
        let result = if let Some(ref handle) = self.persistent_quick_saves {
            handle.flush()
        } else if let Some(ref root) = self.resolved_root {
            crate::quicksave_persistence::snapshot_quick_saves_for_persistence(root)
        } else {
            return;
        };
        match result {
            Ok(report) if report.backed_up_count > 0 => {
                self.log_lines.push(format!(
                    ">>> [QUICKSAVE] Backed up {} co-op quick save(s) to {}.",
                    report.backed_up_count,
                    report.backup_dir.display()
                ));
            }
            Ok(_) => {}
            Err(error) => {
                self.log_lines.push(format!(
                    ">>> [QUICKSAVE] Final backup on exit failed: {:#}",
                    error
                ));
            }
        }
    }

    fn stop_persistent_quick_saves(&mut self) {
        if let Some(mut quicksaves) = self.persistent_quick_saves.take() {
            quicksaves.stop();
        }
    }

    fn restore_quick_saves_before_launch(&mut self, game_root: &Path) {
        if !self.patch_flags.runtime_quicksave_persistence {
            return;
        }
        self.sync_quicksave_worker();
        match crate::quicksave_persistence::restore_latest_quick_saves(game_root) {
            Ok(report) => {
                if report.backed_up_count > 0 {
                    self.log_lines.push(format!(
                        ">>> [QUICKSAVE] Preserved {} newer live quick save(s) into {}.",
                        report.backed_up_count,
                        report.backup_dir.display()
                    ));
                }
                if report.restored_count > 0 {
                    self.log_lines.push(format!(
                        ">>> [QUICKSAVE] Restored {} previous co-op quick save(s) to {}.",
                        report.restored_count,
                        report.profile_dir.display()
                    ));
                }
            }
            Err(error) => {
                self.log_lines.push(format!(
                    ">>> [QUICKSAVE] Could not restore previous co-op quick saves: {:#}",
                    error
                ));
            }
        }
    }

    fn apply_patch_flags_background(&mut self, ctx: &egui::Context) {
        let Some(root) = self.resolved_root.clone() else {
            return;
        };
        if self.applying_flags
            || self.state == InstallState::Installing
            || self.state == InstallState::Uninstalling
        {
            return;
        }
        self.applying_flags = true;
        let flags = self.patch_flags;
        let tx = self.sender.clone();
        let tx_status = self.sender.clone();
        let ctx_clone = ctx.clone();
        let ctx_finish = ctx.clone();

        crate::patcher::set_log_sink(move |msg| {
            let _ = tx.send(GuiEvent::Log(msg.to_string()));
            ctx_clone.request_repaint();
        });

        thread::spawn(move || {
            let res = crate::patcher::sync_mod_flags(&root, &flags, None);
            match res {
                Ok(()) => {
                    let _ = tx_status.send(GuiEvent::Log(format!(
                        ">>> [PATCHES] Applied to game files: {}",
                        flags.summary_line()
                    )));
                    let _ = tx_status.send(GuiEvent::FlagsApplyDone {
                        ok: true,
                        applied: Some(flags),
                    });
                }
                Err(e) => {
                    let _ = tx_status.send(GuiEvent::Log(format!(
                        ">>> [PATCHES ERROR] Could not apply flags (make sure Chaos Theory is closed): {:#}",
                        e
                    )));
                    let _ = tx_status.send(GuiEvent::FlagsApplyDone {
                        ok: false,
                        applied: None,
                    });
                }
            }
            crate::patcher::clear_log_sink();
            ctx_finish.request_repaint();
        });
    }

    fn prepare_mod_flags_before_launch(
        &mut self,
        game_root: &Path,
        direct_target: Option<(Ipv4Addr, u16, u16)>,
    ) -> bool {
        if let Err(e) = crate::patcher::sync_mod_flags(game_root, &self.patch_flags, direct_target) {
            self.log_lines.push(format!(
                ">>> [LAUNCH ERROR] Could not sync mod flags before launch (make sure Chaos Theory is closed first): {:#}",
                e
            ));
            return false;
        }
        self.applied_flags = Some(self.patch_flags);
        self.log_lines.push(format!(
            ">>> [PATCHES] Active for launch: {}",
            self.patch_flags.summary_line()
        ));
        true
    }

    fn render_debug_patch_toggles(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let mut qs_toggled = false;
        ui.horizontal_wrapped(|ui| {
            if ui
                .button(RichText::new("All Standard ON (26/28)").size(11.0))
                .on_hover_text(
                    "Enables all 26 standard Co-op Mod features (keeps Checksum Disconnect Bypass and execAddPlayerInZones AI Zone Wake OFF)",
                )
                .clicked()
            {
                self.patch_flags = crate::patcher::ModFlags::standard_coop();
                qs_toggled = true;
            }
            if ui
                .button(RichText::new("Min Sync (Net + #4/#6 + Diag)").size(11.0))
                .on_hover_text(
                    "Enables ONLY Multi-NIC/NAT networking, #4 AI Vis Cull, #6 Controller Checksum, and Trace/Desync Diagnostics",
                )
                .clicked()
            {
                self.patch_flags = crate::patcher::ModFlags::minimal_coop_sync();
                qs_toggled = true;
            }
            if ui
                .button(RichText::new("Net Only (2/28)").size(11.0))
                .on_hover_text(
                    "Enables ONLY Multi-NIC LAN & Direct-IP NAT hooks; reverts all gameplay, menu, UMD, MapRotation, and UPK changes to vanilla",
                )
                .clicked()
            {
                self.patch_flags = crate::patcher::ModFlags::net_only();
                qs_toggled = true;
            }
            if ui
                .button(RichText::new("All OFF (100% Vanilla)").size(11.0))
                .on_hover_text(
                    "Disables ALL 28 mod flags: restores vanilla EXE, Echelon.u, dynamic-pc.umd, MapRotation.ini, removes *_COOP.* maps, and skips all runtime hooks",
                )
                .clicked()
            {
                self.patch_flags = crate::patcher::ModFlags::all_disabled();
                qs_toggled = true;
            }
        });

        ui.add_space(4.0);
        let is_busy = self.applying_flags
            || self.state == InstallState::Installing
            || self.state == InstallState::Uninstalling;
        let has_pending = self.resolved_root.is_some()
            && self.applied_flags.as_ref() != Some(&self.patch_flags);
        let can_apply = self.resolved_root.is_some() && !is_busy;

        ui.horizontal_wrapped(|ui| {
            let apply_label = if self.applying_flags {
                "⏳ Applying Flags..."
            } else {
                "💾 Apply Flags to Disk"
            };
            let mut apply_btn = egui::Button::new(
                RichText::new(apply_label)
                    .size(11.5)
                    .strong()
                    .color(if can_apply { Color32::WHITE } else { Color32::from_rgb(160, 160, 160) }),
            );
            if has_pending && can_apply {
                apply_btn = apply_btn.fill(Color32::from_rgb(185, 115, 25));
            } else if can_apply {
                apply_btn = apply_btn.fill(Color32::from_rgb(45, 95, 145));
            }
            if ui
                .add_enabled(can_apply, apply_btn)
                .on_hover_text(
                    "Applies all checkbox changes to disk incrementally in the background (also runs automatically before Launch)",
                )
                .clicked()
            {
                self.apply_patch_flags_background(ctx);
            }

            if self.applying_flags {
                ui.label(
                    RichText::new("Syncing disk changes (UMD/UPK updates run off the UI thread)...")
                        .size(11.0)
                        .color(Color32::from_rgb(140, 210, 255)),
                );
            } else if has_pending {
                ui.label(
                    RichText::new("● Pending changes (click Apply or Launch)")
                        .size(11.0)
                        .color(Color32::from_rgb(255, 200, 100)),
                );
            } else if self.applied_flags.is_some() {
                ui.label(
                    RichText::new("✔ Disk matches selected flags")
                        .size(11.0)
                        .color(Color32::from_rgb(110, 220, 130)),
                );
            }
        });

        ui.add_space(4.0);
        for (g_idx, group) in crate::patcher::FlagGroup::ALL.iter().copied().enumerate() {
            let group_descs: Vec<&crate::patcher::FlagDescriptor> = crate::patcher::FLAG_DESCRIPTORS
                .iter()
                .filter(|d| d.group == group)
                .collect();
            let on_count = group_descs
                .iter()
                .filter(|d| (d.get)(&self.patch_flags))
                .count();
            let header_title = format!("{} ({}/{})", group.label(), on_count, group_descs.len());
            egui::CollapsingHeader::new(RichText::new(header_title).size(11.5).strong())
                .id_salt(format!("flag_group_{}", g_idx))
                .default_open(g_idx == 0 || g_idx == 2 || g_idx == 4)
                .show(ui, |ui| {
                    for d in &group_descs {
                        let label_text = if d.requires_heavy_rebuild {
                            RichText::new(format!("{} [UMD/UPK]", d.label))
                                .size(11.0)
                                .color(Color32::from_rgb(225, 210, 160))
                        } else {
                            RichText::new(d.label).size(11.0)
                        };
                        let mut val = (d.get)(&self.patch_flags);
                        if ui.checkbox(&mut val, label_text).on_hover_text(d.tooltip).changed() {
                            *(d.get_mut)(&mut self.patch_flags) = val;
                            if d.short_name == "quicksave_persist" {
                                qs_toggled = true;
                            }
                        }
                    }
                });
        }

        if qs_toggled {
            self.sync_quicksave_worker();
        }
    }

    fn cancel_matching(&mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(());
        }

        // Notify server of session disconnection if a room was registered/matched
        match &self.match_state {
            MatchState::Hosting { code, .. } => {
                let code_clone = code.clone();
                let host = self.server_host.clone();
                let port = self.api_port;
                thread::spawn(move || {
                    let _ = crate::stun::notify_server_disconnect(
                        &host,
                        port,
                        &code_clone,
                        Some("Host cancelled session"),
                    );
                });
            }
            MatchState::Matched { code, .. } => {
                let code_clone = code.clone();
                let host = self.server_host.clone();
                let port = self.api_port;
                thread::spawn(move || {
                    let _ = crate::stun::notify_server_disconnect(
                        &host,
                        port,
                        &code_clone,
                        Some("Player disconnected"),
                    );
                });
            }
            _ => {}
        }

        self.disconnect_keepalive();
        self.stop_session_monitor();
        self.match_state = MatchState::Idle;
    }

    fn start_hosting(&mut self, ctx: &egui::Context) {
        self.cancel_matching();
        self.disconnect_notice = None;
        let (cancel_tx, cancel_rx) = channel();
        self.cancel_tx = Some(cancel_tx);
        self.match_state = MatchState::Hosting {
            code: "Connecting...".to_string(),
            status_text: "Connecting to server...".to_string(),
        };

        let server_host = self.server_host.clone();
        let stun_port = self.stun_port;
        let api_port = self.api_port;
        let bind_ip = self.selected_bind_ip;
        let tx = self.sender.clone();
        let ctx_clone = ctx.clone();

        thread::spawn(move || {
            run_host_match(
                server_host,
                stun_port,
                api_port,
                bind_ip,
                tx,
                cancel_rx,
                ctx_clone,
            );
        });
    }

    fn start_joining(&mut self, ctx: &egui::Context) {
        let code = crate::stun::normalize_friend_code(&self.guest_code_input);
        if code.len() != 5 {
            self.match_state = MatchState::Failed {
                error: "Friend code must be 5 characters (letters/numbers).".to_string(),
            };
            return;
        }
        self.guest_code_input = code.clone();
        self.cancel_matching();
        self.disconnect_notice = None;
        self.match_state = MatchState::Joining {
            target_code: code.clone(),
            status_text: format!("Contacting server to match code '{}'...", code),
        };

        let server_host = self.server_host.clone();
        let stun_port = self.stun_port;
        let api_port = self.api_port;
        let bind_ip = self.selected_bind_ip;
        let tx = self.sender.clone();
        let ctx_clone = ctx.clone();

        thread::spawn(move || {
            run_join_match(server_host, stun_port, api_port, bind_ip, code, tx, ctx_clone);
        });
    }

    fn launch_match_game(&mut self, ctx: &egui::Context) {
        let (is_host, peer_ip, peer_disco_port, peer_game_port, already_launched) =
            match self.match_state {
                MatchState::Matched {
                    is_host,
                    peer_ip,
                    peer_disco_port,
                    peer_game_port,
                    game_launched,
                    ..
                } => (
                    is_host,
                    peer_ip,
                    peer_disco_port,
                    peer_game_port,
                    game_launched,
                ),
                _ => return,
            };

        if already_launched {
            self.log_lines
                .push("  [LAUNCH] Game already running for this session!".to_string());
            return;
        }

        let Some(root) = self.resolved_root.clone() else {
            self.log_lines
                .push("  [LAUNCH] ERROR: Game folder not selected!".to_string());
            return;
        };

        let sys_dir = crate::patcher::find_child_ci(&root, "System");
        let exe_path = crate::patcher::find_child_ci(&sys_dir, "splintercell3.exe");
        if !exe_path.exists() {
            self.log_lines.push(format!(
                "  [LAUNCH] ERROR: Executable not found at {}",
                exe_path.display()
            ));
            return;
        }

        self.stop_keepalive();

        if !self.prepare_mod_flags_before_launch(&root, Some((peer_ip, peer_disco_port, peer_game_port)))
        {
            ctx.request_repaint();
            return;
        }

        self.restore_quick_saves_before_launch(&root);

        let peer_role = if is_host {
            crate::trace::PeerRole::Host
        } else {
            crate::trace::PeerRole::Guest
        };
        let launch_opts = self.build_launch_runtime_options();
        match crate::launcher::launch_game(
            &exe_path,
            &root,
            peer_role,
            Some(crate::launcher::DirectPeerTarget {
                ip: peer_ip,
                disco_port: peer_disco_port,
                game_port: peer_game_port,
            }),
            self.selected_bind_ip,
            launch_opts,
        ) {
            Ok(proc) => {
                let pid = proc.pid;
                self.active_game_pids
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(pid);
                if let MatchState::Matched {
                    ref mut game_launched,
                    ..
                } = self.match_state
                {
                    *game_launched = true;
                }
                spawn_game_monitor(proc, self.sender.clone(), ctx.clone(), root.clone());
                self.log_lines.push(format!(
                    ">>> Chaos Theory Coop launched successfully (PID: {})!",
                    pid
                ));
                self.log_lines
                    .push(">>> Connected directly to your friend!".to_string());
                if is_host {
                    self.log_lines.push(
                        ">>> [HOST]: In game, select Coop -> Enhanced Coop -> Host Game to create your match."
                            .to_string(),
                    );
                } else {
                    self.log_lines.push(
                        ">>> [GUEST]: In game, select Coop -> Enhanced Coop to find and join your friend's game."
                            .to_string(),
                    );
                }
            }
            Err(e) => {
                self.log_lines
                    .push(format!(">>> [LAUNCH ERROR] Failed to launch game: {:#}", e));
            }
        }
        ctx.request_repaint();
    }

    fn attach_matched_game(&mut self, ctx: &egui::Context) {
        let (is_host, peer_ip, peer_disco_port, peer_game_port, already_launched) =
            match self.match_state {
                MatchState::Matched {
                    is_host,
                    peer_ip,
                    peer_disco_port,
                    peer_game_port,
                    game_launched,
                    ..
                } => (
                    is_host,
                    peer_ip,
                    peer_disco_port,
                    peer_game_port,
                    game_launched,
                ),
                _ => return,
            };

        if already_launched {
            self.log_lines
                .push("  [ATTACH] Game already attached/running for this session!".to_string());
            return;
        }

        let Some(root) = self.resolved_root.clone() else {
            self.log_lines
                .push("  [ATTACH] ERROR: Game folder not selected!".to_string());
            return;
        };

        let running = crate::launcher::find_running_scct_processes();
        let active_snapshot = self.active_pids_sorted();
        let target = running
            .iter()
            .find(|info| !active_snapshot.contains(&info.pid))
            .or_else(|| running.first());
        let Some(info) = target else {
            self.log_lines.push(
                ">>> [ATTACH] No running splintercell3.exe found. Start Chaos Theory first (e.g. via Steam or Nucleus), then click Attach."
                    .to_string(),
            );
            ctx.request_repaint();
            return;
        };

        self.stop_keepalive();
        self.restore_quick_saves_before_launch(&root);

        let peer_role = if is_host {
            crate::trace::PeerRole::Host
        } else {
            crate::trace::PeerRole::Guest
        };
        let launch_opts = self.build_launch_runtime_options();
        match crate::launcher::attach_game(
            info.pid,
            peer_role,
            Some(crate::launcher::DirectPeerTarget {
                ip: peer_ip,
                disco_port: peer_disco_port,
                game_port: peer_game_port,
            }),
            self.selected_bind_ip,
            launch_opts,
        ) {
            Ok((mut proc, updated_info)) => {
                proc.reserve_session_paths(&root);
                let pid = proc.pid;
                self.active_game_pids
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(pid);
                if let MatchState::Matched {
                    ref mut game_launched,
                    ..
                } = self.match_state
                {
                    *game_launched = true;
                }
                spawn_game_monitor(proc, self.sender.clone(), ctx.clone(), root.clone());
                self.log_lines.push(format!(
                    ">>> [ATTACH] Attached to {} and injected peer target!",
                    updated_info.summary_line()
                ));
                if !updated_info.has_mod_net_caves {
                    self.log_lines.push(
                        ">>> [ATTACH WARNING] Running EXE lacks SCCT Enhanced Coop PE network caves. Install Mod before launching the game (and clear Nucleus cached content if using Nucleus)."
                            .to_string(),
                    );
                }
                self.log_lines.push(
                    ">>> In game, enter Coop -> Enhanced Coop (if already in the Coop menu, back out to Main Menu and re-enter)."
                        .to_string(),
                );
            }
            Err(e) => {
                self.log_lines
                    .push(format!(">>> [ATTACH ERROR] Failed to attach PID {}: {:#}", info.pid, e));
            }
        }
        ctx.request_repaint();
    }

    fn attach_running_games_once(&mut self, ctx: &egui::Context) {
        let Some(root) = self.resolved_root.clone() else {
            self.log_lines
                .push("  [ATTACH] ERROR: Game folder not selected!".to_string());
            return;
        };
        let net_mode = match self.selected_nucleus_net_mode() {
            Ok(m) => m,
            Err(e) => {
                self.log_lines
                    .push(format!(">>> [NUCLEUS ERROR] Invalid IP pair: {:#}", e));
                return;
            }
        };

        let _ = crate::launcher::prepare_exe_for_nucleus_lan(
            &root,
            self.patch_flags.runtime_bypass_checksum_disconnect,
        );
        self.restore_quick_saves_before_launch(&root);

        let running = crate::launcher::find_running_scct_processes();
        if running.is_empty() {
            self.log_lines.push(
                ">>> [ATTACH] No running splintercell3.exe instances found. Start Nucleus Co-op first, or use 'Watch & Auto-Attach'."
                    .to_string(),
            );
            ctx.request_repaint();
            return;
        }

        let launch_opts = self.build_launch_runtime_options();
        let mut attached_count = 0usize;
        let mut reconfigured_count = 0usize;
        for (slot, info) in running.into_iter().enumerate() {
            let already_tracked = self
                .active_game_pids
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&info.pid);
            let mut plan = crate::launcher::plan_nucleus_instance(slot, net_mode, &info);
            if matches!(net_mode, crate::launcher::NucleusNetMode::PreserveNucleusLan)
                && self.selected_bind_ip.is_some()
            {
                plan.local_bind_ip = self.selected_bind_ip;
            }
            if already_tracked {
                match crate::launcher::reconfigure_running_game_network(
                    info.pid,
                    plan.direct_peer,
                    plan.local_bind_ip,
                    launch_opts,
                ) {
                    Ok(updated_info) => {
                        reconfigured_count += 1;
                        self.log_lines.push(format!(
                            ">>> [NUCLEUS] Re-applied network mode to Instance #{} — {}",
                            slot + 1,
                            updated_info.summary_line()
                        ));
                        if !updated_info.has_mod_net_caves {
                            self.log_lines.push(
                                ">>> [NUCLEUS WARNING] Running EXE has missing or outdated PE network caves! Close both games, delete Nucleus's cached 'content' folder for Chaos Theory, click Reinstall, then relaunch Nucleus."
                                    .to_string(),
                            );
                        }
                        if let Some(warn) = plan.warning {
                            self.log_lines.push(format!(">>> [NUCLEUS NOTE] {}", warn));
                        }
                    }
                    Err(e) => {
                        self.log_lines.push(format!(
                            ">>> [NUCLEUS ERROR] Failed to re-apply network mode to PID {}: {:#}",
                            info.pid, e
                        ));
                    }
                }
                continue;
            }

            match crate::launcher::attach_game(
                info.pid,
                plan.role,
                plan.direct_peer,
                plan.local_bind_ip,
                launch_opts,
            ) {
                Ok((mut proc, updated_info)) => {
                    proc.reserve_session_paths(&root);
                    let pid = proc.pid;
                    self.active_game_pids
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(pid);
                    spawn_game_monitor(proc, self.sender.clone(), ctx.clone(), root.clone());
                    attached_count += 1;
                    self.log_lines.push(format!(
                        ">>> [NUCLEUS] Attached Instance #{} — {}",
                        slot + 1,
                        updated_info.summary_line()
                    ));
                    if !updated_info.has_mod_net_caves {
                        self.log_lines.push(
                            ">>> [NUCLEUS WARNING] Running EXE has missing or outdated PE network caves! Close both games, delete Nucleus's cached 'content' folder for Chaos Theory, click Reinstall, then relaunch Nucleus."
                                .to_string(),
                        );
                    }
                    if let Some(warn) = plan.warning {
                        self.log_lines.push(format!(">>> [NUCLEUS NOTE] {}", warn));
                    }
                }
                Err(e) => {
                    self.log_lines.push(format!(
                        ">>> [NUCLEUS ERROR] Failed to attach PID {}: {:#}",
                        info.pid, e
                    ));
                }
            }
        }
        self.nucleus_next_slot = attached_count + reconfigured_count;

        if attached_count > 0 || reconfigured_count > 0 {
            self.log_lines.push(
                ">>> [NUCLEUS] Ready! In both game windows, go to Co-op -> Enhanced Coop (if already inside the Co-op menu, back out to Main Menu and re-enter so sockets rebind)."
                    .to_string(),
            );
        }
        ctx.request_repaint();
    }

    fn start_nucleus_watcher(&mut self, ctx: &egui::Context) {
        let Some(root) = self.resolved_root.clone() else {
            self.log_lines
                .push("  [NUCLEUS] ERROR: Game folder not selected!".to_string());
            return;
        };
        let net_mode = match self.selected_nucleus_net_mode() {
            Ok(m) => m,
            Err(e) => {
                self.log_lines
                    .push(format!(">>> [NUCLEUS ERROR] Invalid IP pair: {:#}", e));
                return;
            }
        };
        self.stop_nucleus_watcher();

        match crate::launcher::prepare_exe_for_nucleus_lan(
            &root,
            self.patch_flags.runtime_bypass_checksum_disconnect,
        ) {
            Ok(true) => {
                self.log_lines.push(
                    ">>> [NUCLEUS] Cleared stale online Friend-Code target on disk for LAN/Nucleus."
                        .to_string(),
                );
            }
            Ok(false) => {}
            Err(e) => {
                self.log_lines.push(format!(
                    ">>> [NUCLEUS] Warning pre-cleaning splintercell3.exe on disk: {:#}",
                    e
                ));
            }
        }
        self.restore_quick_saves_before_launch(&root);

        let (stop_tx, stop_rx) = channel::<()>();
        let active_pids = Arc::clone(&self.active_game_pids);
        let tx = self.sender.clone();
        let ctx_clone = ctx.clone();
        let launch_opts = self.build_launch_runtime_options();
        let bind_ip = self.selected_bind_ip;

        // If any instances are already attached from a previous mode, re-apply the selected mode right away.
        let mut initial_slot = 0usize;
        let existing_running = crate::launcher::find_running_scct_processes();
        for info in existing_running {
            let already_tracked = active_pids
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&info.pid);
            if !already_tracked {
                continue;
            }
            let mut plan = crate::launcher::plan_nucleus_instance(initial_slot, net_mode, &info);
            if matches!(net_mode, crate::launcher::NucleusNetMode::PreserveNucleusLan)
                && bind_ip.is_some()
            {
                plan.local_bind_ip = bind_ip;
            }
            match crate::launcher::reconfigure_running_game_network(
                info.pid,
                plan.direct_peer,
                plan.local_bind_ip,
                launch_opts,
            ) {
                Ok(updated_info) => {
                    self.log_lines.push(format!(
                        ">>> [NUCLEUS] Re-applied network mode to Instance #{} — {}",
                        initial_slot + 1,
                        updated_info.summary_line()
                    ));
                }
                Err(e) => {
                    self.log_lines.push(format!(
                        ">>> [NUCLEUS ERROR] Failed to re-apply network mode to PID {}: {:#}",
                        info.pid, e
                    ));
                }
            }
            initial_slot += 1;
        }
        self.nucleus_next_slot = initial_slot;

        self.log_lines.push(format!(
            ">>> [NUCLEUS] Watching for splintercell3.exe launches ({})... Click Play in Nucleus Co-op now!",
            self.nucleus_net_mode.label()
        ));

        let join_handle = thread::spawn(move || {
            let mut pending: HashMap<u32, Instant> = HashMap::new();
            let mut failed_pids: HashSet<u32> = HashSet::new();
            let mut next_slot = initial_slot;

            loop {
                let running = crate::launcher::find_running_scct_processes();
                let live_set: HashSet<u32> = running.iter().map(|i| i.pid).collect();
                pending.retain(|pid, _| live_set.contains(pid));
                failed_pids.retain(|pid| live_set.contains(pid));

                for info in running {
                    let already_active = active_pids
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .contains(&info.pid);
                    if already_active || failed_pids.contains(&info.pid) {
                        continue;
                    }
                    let first_seen = *pending.entry(info.pid).or_insert_with(Instant::now);
                    if first_seen.elapsed() < Duration::from_millis(1500)
                        || !crate::launcher::is_process_initialized_for_attach(info.pid)
                    {
                        continue;
                    }
                    pending.remove(&info.pid);

                    // Reset slot numbering cleanly when starting a fresh Nucleus Co-op session
                    if active_pids
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .is_empty()
                    {
                        next_slot = 0;
                    }

                    let mut plan = crate::launcher::plan_nucleus_instance(next_slot, net_mode, &info);
                    if matches!(net_mode, crate::launcher::NucleusNetMode::PreserveNucleusLan)
                        && bind_ip.is_some()
                    {
                        plan.local_bind_ip = bind_ip;
                    }
                    match crate::launcher::attach_game(
                        info.pid,
                        plan.role,
                        plan.direct_peer,
                        plan.local_bind_ip,
                        launch_opts,
                    ) {
                        Ok((mut proc, updated_info)) => {
                            proc.reserve_session_paths(&root);
                            let pid = proc.pid;
                            active_pids
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(pid);
                            let _ = tx.send(GuiEvent::GameAttached(pid));
                            let _ = tx.send(GuiEvent::Log(format!(
                                ">>> [NUCLEUS] Auto-attached Instance #{} — {}",
                                next_slot + 1,
                                updated_info.summary_line()
                            )));
                            if !updated_info.has_mod_net_caves {
                                let _ = tx.send(GuiEvent::Log(
                                    ">>> [NUCLEUS WARNING] Running EXE lacks SCCT Enhanced Coop PE network caves! Delete Nucleus's cached 'content' folder for Chaos Theory, run Install Mod, then relaunch Nucleus."
                                        .to_string(),
                                ));
                            }
                            if let Some(warn) = plan.warning {
                                let _ = tx.send(GuiEvent::Log(format!(
                                    ">>> [NUCLEUS NOTE] {}",
                                    warn
                                )));
                            }
                            spawn_game_monitor(proc, tx.clone(), ctx_clone.clone(), root.clone());
                            next_slot += 1;
                            ctx_clone.request_repaint();
                        }
                        Err(e) => {
                            failed_pids.insert(info.pid);
                            let _ = tx.send(GuiEvent::Log(format!(
                                ">>> [NUCLEUS ERROR] Failed to attach PID {}: {:#}",
                                info.pid, e
                            )));
                            ctx_clone.request_repaint();
                        }
                    }
                }

                match stop_rx.recv_timeout(Duration::from_millis(250)) {
                    Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        });

        self.nucleus_watcher = Some(NucleusWatcherHandle {
            stop_tx,
            join_handle: Some(join_handle),
        });
        ctx.request_repaint();
    }

    fn launch_direct_game(&mut self, ctx: &egui::Context) {
        let Some(root) = self.resolved_root.clone() else {
            self.log_lines
                .push("  [LAUNCH] ERROR: Game folder not selected!".to_string());
            return;
        };

        let sys_dir = crate::patcher::find_child_ci(&root, "System");
        let exe_path = crate::patcher::find_child_ci(&sys_dir, "splintercell3.exe");
        if !exe_path.exists() {
            self.log_lines.push(format!(
                "  [LAUNCH] ERROR: Executable not found at {}",
                exe_path.display()
            ));
            return;
        }

        self.stop_keepalive();

        if !self.prepare_mod_flags_before_launch(&root, None) {
            ctx.request_repaint();
            return;
        }

        self.restore_quick_saves_before_launch(&root);

        let launch_opts = self.build_launch_runtime_options();
        match crate::launcher::launch_game(
            &exe_path,
            &root,
            crate::trace::PeerRole::LanOrDirect,
            None,
            self.selected_bind_ip,
            launch_opts,
        ) {
            Ok(proc) => {
                let pid = proc.pid;
                self.active_game_pids
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(pid);
                spawn_game_monitor(proc, self.sender.clone(), ctx.clone(), root.clone());
                let adapter_desc = match self.selected_bind_ip {
                    Some(ip) => format!("bound to adapter {}", ip),
                    None => "all local adapters (Auto)".to_string(),
                };
                self.log_lines.push(format!(
                    ">>> Chaos Theory launched (PID: {}) in LAN mode ({})!",
                    pid, adapter_desc
                ));
                self.log_lines.push(
                    ">>> In game, select Coop -> Enhanced Coop to host or join on your local network."
                        .to_string(),
                );
            }
            Err(e) => {
                self.log_lines
                    .push(format!(">>> [LAUNCH ERROR] Failed to launch game: {:#}", e));
            }
        }
        ctx.request_repaint();
    }
}

impl eframe::App for PatcherApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll for log updates, events, and background tasks
        while let Ok(event) = self.receiver.try_recv() {
            match event {
                GuiEvent::Log(msg) => self.log_lines.push(msg),
                GuiEvent::InstallDone { root, ok } => {
                    self.handle_install_done(&root, ok);
                }
                GuiEvent::UninstallDone { root, ok } => {
                    self.handle_uninstall_done(&root, ok);
                }
                GuiEvent::FlagsApplyDone { ok, applied } => {
                    self.applying_flags = false;
                    if ok {
                        if let Some(root) = self.resolved_root.clone() {
                            self.update_flags_from_disk(&root, applied, false);
                        } else if let Some(flags) = applied {
                            self.applied_flags = Some(flags);
                        }
                        self.sync_quicksave_worker();
                    }
                }
                GuiEvent::FriendCodeRegistered(code) => {
                    self.match_state = MatchState::Hosting {
                        code,
                        status_text: "Waiting for friend to enter your code...".to_string(),
                    };
                }
                GuiEvent::MatchStatus(status) => match &mut self.match_state {
                    MatchState::Hosting { status_text, .. }
                    | MatchState::Joining { status_text, .. } => {
                        *status_text = status;
                    }
                    _ => {}
                },
                GuiEvent::Matched {
                    code,
                    is_host,
                    peer_ip,
                    peer_disco_port,
                    peer_game_port,
                    mut keepalive,
                } => {
                    if matches!(
                        self.match_state,
                        MatchState::Hosting { .. } | MatchState::Joining { .. }
                    ) {
                        self.stop_keepalive();
                        self.stop_session_monitor();
                        self.keepalive = keepalive;
                        self.session_monitor = Some(spawn_session_monitor(
                            self.server_host.clone(),
                            self.api_port,
                            code.clone(),
                            if is_host {
                                "host".to_string()
                            } else {
                                "guest".to_string()
                            },
                            self.sender.clone(),
                            ctx.clone(),
                        ));
                        self.match_state = MatchState::Matched {
                            code,
                            is_host,
                            peer_ip,
                            peer_disco_port,
                            peer_game_port,
                            game_launched: false,
                        };
                    } else if let Some(ref mut ka) = keepalive {
                        ka.stop_and_wait();
                    }
                }
                GuiEvent::MatchFailed(error) => {
                    self.stop_keepalive();
                    self.stop_session_monitor();
                    self.match_state = MatchState::Failed { error };
                }
                GuiEvent::PeerDisconnected(reason) => {
                    self.stop_keepalive();
                    self.stop_session_monitor();
                    self.log_lines.push(format!(">>> [DISCONNECT] {}", reason));
                    self.disconnect_notice = Some(reason);
                    self.match_state = MatchState::Idle;
                }
                GuiEvent::GameAttached(pid) => {
                    self.active_game_pids
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(pid);
                }
                GuiEvent::GameExited(pid) => {
                    let remaining_active = {
                        let mut set = self
                            .active_game_pids
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        set.remove(&pid);
                        set.len()
                    };
                    if remaining_active == 0 {
                        self.nucleus_next_slot = 0;
                    }
                    self.log_lines.push(format!(
                        ">>> Splinter Cell Chaos Theory (PID: {}) has exited.",
                        pid
                    ));
                    self.flush_quicksaves_on_game_exit();
                    if remaining_active == 0
                        && let MatchState::Matched {
                            ref code,
                            game_launched: true,
                            ..
                        } = self.match_state
                    {
                        let code_clone = code.clone();
                        let host = self.server_host.clone();
                        let port = self.api_port;
                        thread::spawn(move || {
                            let _ = crate::stun::notify_server_disconnect(
                                &host,
                                port,
                                &code_clone,
                                Some("Game closed"),
                            );
                        });
                        self.disconnect_keepalive();
                        self.stop_session_monitor();
                        self.match_state = MatchState::Idle;
                        self.disconnect_notice = Some(
                            "Session ended because game was closed. If you're using the Steam version, make sure Steam is running first."
                                .to_string(),
                        );
                        self.log_lines
                            .push(">>> Session closed because game was exited.".to_string());
                    }
                }
                GuiEvent::DesyncDetected(report) => {
                    self.log_lines.push(
                        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                            .to_string(),
                    );
                    self.log_lines.push(
                        ">>> [DESYNC DETECTED] Simulation lockstep mismatch detected between Host and Guest!"
                            .to_string(),
                    );
                    self.log_lines.push(format!(
                        ">>> [MISMATCH SLOTS] {}",
                        report.mismatched_slots
                    ));
                    self.log_lines.push(format!(
                        ">>> [DESYNC DUMP] Diagnostic actor dump saved to: {}",
                        report.dump_path.display()
                    ));
                    if let Some(ref trace_path) = report.trace_path {
                        self.log_lines.push(format!(
                            ">>> [STARTUP TRACE] Startup tick/checksum trace saved to: {}",
                            trace_path.display()
                        ));
                    }
                    self.log_lines.push(
                        ">>> Compare BOTH scct_desync_dump and scct_startup_trace from BOTH peers (Host and Guest)."
                            .to_string(),
                    );
                    self.log_lines.push(
                        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                            .to_string(),
                    );
                }
                GuiEvent::DesyncDumpFailed(err) => {
                    self.log_lines.push(format!(
                        ">>> [DESYNC ERROR] Failed to dump desync diagnostic state: {}",
                        err
                    ));
                }
            }
        }

        let central_frame =
            egui::Frame::central_panel(&ctx.style()).fill(Color32::from_rgb(18, 20, 24));
        egui::CentralPanel::default().frame(central_frame).show(ctx, |ui| {
            ui.add_space(4.0);

            // Title
            ui.heading(
                RichText::new("Splinter Cell: Chaos Theory — Coop Mod")
                    .strong()
                    .size(20.0),
            );
            ui.label(
                RichText::new("Play all Single Player missions in online co-op with friends")
                .size(12.5)
                .color(Color32::from_rgb(180, 180, 180)),
            );

            ui.add_space(6.0);

            // =================================================================
            // Game Folder Picker / Browser Bar
            // =================================================================
            let folder_frame = egui::Frame::group(ui.style())
                .fill(Color32::from_rgb(18, 20, 24))
                .inner_margin(8.0);

            folder_frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Game Folder:").strong().size(12.5));
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.game_dir_input)
                            .desired_width(ui.available_width() - 95.0)
                            .hint_text("Path to Splinter Cell Chaos Theory installation..."),
                    );

                    if resp.changed() {
                        self.check_manual_path_input();
                    }

                    if ui.button(RichText::new("📁 Browse...").size(12.0).strong()).clicked() {
                        let mut dialog = rfd::FileDialog::new()
                            .set_title("Select Splinter Cell Chaos Theory Game Folder");
                        if let Some(ref current) = self.resolved_root {
                            dialog = dialog.set_directory(current);
                        }
                        if let Some(folder) = dialog.pick_folder() {
                            if let Some(valid) = crate::patcher::validate_game_root(&folder) {
                                self.set_game_root(valid);
                            } else {
                                self.game_dir_input = folder.display().to_string();
                                self.clear_game_root(
                                    "System/splintercell3.exe not found in selected folder."
                                        .to_string(),
                                );
                            }
                        }
                    }
                });

                // Status message underneath path
                ui.add_space(2.0);
                if self.resolved_root.is_some() {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("✔").color(Color32::from_rgb(80, 220, 100)).strong());
                        ui.label(
                            RichText::new(&self.detection_msg)
                                .color(Color32::from_rgb(120, 230, 140))
                                .size(11.5),
                        );
                    });
                } else {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("⚠").color(Color32::from_rgb(255, 100, 100)).strong());
                        ui.label(
                            RichText::new(&self.detection_msg)
                                .color(Color32::from_rgb(255, 120, 120))
                                .size(11.5),
                        );
                    });
                }

                // If multiple installations were detected, provide quick-select buttons
                if self.detected_roots.len() > 1 {
                    ui.add_space(3.0);
                    let mut switch_to_root = None;
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new("Detected locations:")
                                .size(11.0)
                                .color(Color32::from_rgb(160, 160, 160)),
                        );
                        for root in &self.detected_roots {
                            let name = root.file_name().and_then(|n| n.to_str()).unwrap_or("Game");
                            let is_current = self.resolved_root.as_ref() == Some(root);
                            let btn_text = if is_current {
                                format!("✔ {}", name)
                            } else {
                                name.to_string()
                            };
                            if ui.button(RichText::new(btn_text).size(11.0)).clicked() {
                                switch_to_root = Some(root.clone());
                            }
                        }
                    });
                    if let Some(root) = switch_to_root {
                        self.set_game_root(root);
                    }
                }
            });

            ui.add_space(6.0);

            // =================================================================
            // Main Action Buttons ("Install Mod" / "Reinstall" + "Uninstall")
            // =================================================================
            let is_busy = self.applying_flags
                || self.state == InstallState::Installing
                || self.state == InstallState::Uninstalling;
            let can_click = !is_busy && self.resolved_root.is_some();

            if let Some(ref ver) = self.installed_version {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Mod Status:").size(12.5).color(Color32::from_rgb(180, 180, 180)));
                    ui.label(
                        RichText::new(format!("✔ Co-op Mod v{} is installed", ver))
                            .size(12.5)
                            .strong()
                            .color(Color32::from_rgb(100, 220, 120)),
                    );
                });
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Network Adapter:")
                            .size(12.0)
                            .color(Color32::from_rgb(180, 180, 180)),
                    );
                    let selected_label = match self.selected_bind_ip {
                        Some(ip) => format!("{}", ip),
                        None => "Auto (All Adapters)".to_string(),
                    };
                    egui::ComboBox::from_id_salt("bind_adapter_ip")
                        .selected_text(selected_label)
                        .width(185.0)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.selected_bind_ip,
                                None,
                                "Auto (All Adapters)",
                            );
                            for &ip in &self.available_local_ips {
                                ui.selectable_value(
                                    &mut self.selected_bind_ip,
                                    Some(ip),
                                    format!("{}", ip),
                                );
                            }
                        })
                        .response
                        .on_hover_text(
                            "Optional: pin game sockets to one specific local IPv4 adapter (useful for multi-NIC PCs or two instances on the same PC)",
                        );
                    if ui
                        .button(RichText::new("🔄").size(11.5))
                        .on_hover_text("Refresh detected local IPv4 adapters")
                        .clicked()
                    {
                        self.available_local_ips = crate::ip::get_all_local_ips();
                    }
                });
                if self.dev_mode {
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.checkbox(
                            &mut self.auto_resync,
                            RichText::new("⚡ Auto-Resync on Desync (Experimental)").size(11.5),
                        )
                        .on_hover_text(
                            "Stage 1 in-memory Host -> Client state resync when a lockstep checksum mismatch occurs (prevents desync disconnects without reloading)",
                        );
                    });
                }
                ui.add_space(4.0);

                let mut action_launch_direct = false;
                ui.columns(3, |cols| {
                    // Direct LAN Launch Button
                    let btn_launch = egui::Button::new(
                        RichText::new("🚀 Launch Game (LAN)")
                            .size(13.5)
                            .strong()
                            .color(Color32::WHITE),
                    )
                    .fill(Color32::from_rgb(32, 140, 60))
                    .min_size(Vec2::new(cols[0].available_width(), 36.0));

                    if cols[0].add_enabled(can_click, btn_launch).clicked() {
                        action_launch_direct = true;
                    }

                    // Reinstall Button
                    let reinstall_text = match self.state {
                        InstallState::Installing => "Installing...",
                        _ => "🔄 Reinstall",
                    };
                    let btn_reinstall = egui::Button::new(
                        RichText::new(reinstall_text).size(13.5).strong().color(
                            if can_click {
                                Color32::WHITE
                            } else {
                                Color32::from_rgb(160, 160, 160)
                            },
                        ),
                    )
                    .min_size(Vec2::new(cols[1].available_width(), 36.0));

                    if cols[1].add_enabled(can_click, btn_reinstall).clicked() {
                        self.start_install_task(
                            ctx,
                            "\n>>> Reinstallation complete! All coop missions and network fixes re-applied.",
                        );
                    }

                    // Uninstall Button
                    let uninstall_text = match self.state {
                        InstallState::Uninstalling => "Uninstalling...",
                        _ => "🗑 Uninstall",
                    };
                    let btn_uninstall = egui::Button::new(
                        RichText::new(uninstall_text).size(13.5).strong().color(
                            if can_click {
                                Color32::from_rgb(255, 180, 180)
                            } else {
                                Color32::from_rgb(160, 160, 160)
                            },
                        ),
                    )
                    .min_size(Vec2::new(cols[2].available_width(), 36.0));

                    if cols[2].add_enabled(can_click, btn_uninstall).clicked() {
                        self.state = InstallState::Uninstalling;
                        self.log_lines.clear();

                        let tx = self.sender.clone();
                        let tx_status = self.sender.clone();
                        let ctx_clone = ctx.clone();
                        let root = self.resolved_root.clone().unwrap();

                        crate::patcher::set_log_sink(move |msg| {
                            let _ = tx.send(GuiEvent::Log(msg.to_string()));
                            ctx_clone.request_repaint();
                        });

                        let ctx_finish = ctx.clone();
                        thread::spawn(move || {
                            let res = crate::patcher::restore_vanilla(&root);
                            match res {
                                Ok(_) => {
                                    let _ = tx_status.send(GuiEvent::Log("\n>>> Uninstallation complete! Restored 100% vanilla game files.".to_string()));
                                    let _ = tx_status.send(GuiEvent::UninstallDone { root, ok: true });
                                }
                                Err(e) => {
                                    let _ = tx_status.send(GuiEvent::Log(format!("\n>>> ERROR: {:#}", e)));
                                    let _ = tx_status.send(GuiEvent::UninstallDone { root, ok: false });
                                }
                            }
                            crate::patcher::clear_log_sink();
                            ctx_finish.request_repaint();
                        });
                    }
                });

                if action_launch_direct {
                    self.launch_direct_game(ctx);
                }
            } else {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Mod Status:").size(12.5).color(Color32::from_rgb(180, 180, 180)));
                    ui.label(
                        RichText::new("Not Installed (Vanilla game)")
                            .size(12.5)
                            .color(Color32::from_rgb(200, 200, 200)),
                    );
                });
                ui.add_space(4.0);

                let button_text = install_button_label(&self.state);

                let btn = egui::Button::new(
                    RichText::new(button_text).size(15.0).strong().color(
                        if can_click {
                            Color32::WHITE
                        } else {
                            Color32::from_rgb(160, 160, 160)
                        },
                    ),
                )
                .min_size(Vec2::new(ui.available_width(), 36.0));

                if ui.add_enabled(can_click, btn).clicked() {
                    self.start_install_task(
                        ctx,
                        "\n>>> Installation complete! You can now use the Friend Code section below to play online with friends.",
                    );
                }
            }

            ui.add_space(6.0);

            // =================================================================
            // Online Co-op (Friend Code) Section
            // =================================================================
            let online_frame = egui::Frame::group(ui.style())
                .fill(Color32::from_rgb(20, 24, 30))
                .inner_margin(12.0);

            online_frame.show(ui, |ui| {
                ui.heading(
                    RichText::new("🌐 Online Co-op with Friends")
                        .size(15.0)
                        .strong(),
                );

                ui.add_space(6.0);

                let mut action_cancel = false;
                let mut action_launch = false;
                let mut action_attach_match = false;

                match &mut self.match_state {
                    MatchState::Idle => {
                        let mut clear_notice = false;
                        if let Some(notice) = &self.disconnect_notice {
                            let notice_frame = egui::Frame::group(ui.style())
                                .fill(Color32::from_rgb(38, 26, 26))
                                .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(220, 100, 80)))
                                .inner_margin(10.0);
                            notice_frame.show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(format!("⚠ {}", notice))
                                            .color(Color32::from_rgb(255, 140, 140))
                                            .size(13.0)
                                            .strong(),
                                    );
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.button(RichText::new("✕").size(11.0)).clicked() {
                                            clear_notice = true;
                                        }
                                    });
                                });
                            });
                            ui.add_space(8.0);
                        }
                        if clear_notice {
                            self.disconnect_notice = None;
                        }

                        ui.columns(2, |cols| {
                            // Left Column: Host a Session
                            let left_frame = egui::Frame::group(cols[0].style())
                                .fill(Color32::from_rgb(26, 33, 44))
                                .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(50, 62, 80)))
                                .inner_margin(14.0);
                            left_frame.show(&mut cols[0], |ui| {
                                ui.label(RichText::new("Host a Game").strong().size(15.0).color(Color32::WHITE));
                                ui.label(
                                    RichText::new(
                                        "Generates a 5-letter code to give to your friend to connect.",
                                    )
                                    .size(12.0)
                                    .color(Color32::from_rgb(180, 190, 205)),
                                );
                                ui.add_space(10.0);
                                let host_btn = egui::Button::new(
                                    RichText::new("🎮 Host Game")
                                        .size(14.5)
                                        .strong()
                                        .color(Color32::WHITE),
                                )
                                .fill(Color32::from_rgb(35, 100, 180))
                                .min_size(Vec2::new(ui.available_width(), 38.0));

                                if ui.add(host_btn).clicked() {
                                    self.start_hosting(ctx);
                                }
                            });

                            // Right Column: Join a Friend
                            let right_frame = egui::Frame::group(cols[1].style())
                                .fill(Color32::from_rgb(26, 33, 44))
                                .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(50, 62, 80)))
                                .inner_margin(14.0);
                            right_frame.show(&mut cols[1], |ui| {
                                ui.label(RichText::new("Join a Friend").strong().size(15.0).color(Color32::WHITE));
                                ui.label(
                                    RichText::new(
                                        "Enter your friend's 5-letter code to connect directly.",
                                    )
                                    .size(12.0)
                                    .color(Color32::from_rgb(180, 190, 205)),
                                );
                                ui.add_space(10.0);
                                ui.horizontal(|ui| {
                                    let resp = ui.add(
                                        egui::TextEdit::singleline(&mut self.guest_code_input)
                                            .char_limit(5)
                                            .font(egui::FontId::monospace(26.0))
                                            .vertical_align(egui::Align::Center)
                                            .desired_width(120.0)
                                            .min_size(Vec2::new(120.0, 38.0))
                                            .hint_text("K7X9B"),
                                    );
                                    if resp.changed() {
                                        self.guest_code_input =
                                            crate::stun::normalize_friend_code(&self.guest_code_input);
                                    }

                                    let can_join = self.guest_code_input.len() == 5;
                                    let join_btn = egui::Button::new(
                                        RichText::new("🔗 Join Game")
                                            .size(14.5)
                                            .strong()
                                            .color(if can_join {
                                                Color32::WHITE
                                            } else {
                                                Color32::from_rgb(160, 165, 175)
                                            }),
                                    )
                                    .fill(if can_join {
                                        Color32::from_rgb(35, 100, 180)
                                    } else {
                                        Color32::from_rgb(45, 55, 68)
                                    })
                                    .min_size(Vec2::new(ui.available_width(), 38.0));

                                    if ui.add_enabled(can_join, join_btn).clicked() {
                                        self.start_joining(ctx);
                                    }
                                });
                            });
                        });
                    }

                    MatchState::Hosting { code, status_text } => {
                        let host_box = egui::Frame::group(ui.style())
                            .fill(Color32::from_rgb(24, 34, 46))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(60, 120, 200)))
                            .inner_margin(14.0);
                        let cur_code = code.clone();
                        let cur_status = status_text.clone();
                        host_box.show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Your Friend Code:").strong().size(13.5));
                                ui.label(
                                    RichText::new(&cur_code)
                                        .monospace()
                                        .size(18.0)
                                        .strong()
                                        .color(Color32::from_rgb(120, 220, 255)),
                                );

                                if ui.button(RichText::new("📋 Copy Code").size(11.5)).clicked() {
                                    ctx.copy_text(cur_code.clone());
                                }

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button(RichText::new("❌ Cancel").size(11.5)).clicked() {
                                        action_cancel = true;
                                    }
                                });
                            });

                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(
                                    RichText::new(&cur_status)
                                        .size(12.0)
                                        .color(Color32::from_rgb(200, 220, 240)),
                                );
                            });
                        });
                    }

                    MatchState::Joining {
                        target_code,
                        status_text,
                    } => {
                        let join_box = egui::Frame::group(ui.style())
                            .fill(Color32::from_rgb(24, 34, 46))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(60, 120, 200)))
                            .inner_margin(14.0);
                        let cur_target = target_code.clone();
                        let cur_status = status_text.clone();
                        join_box.show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Joining Friend Code:").strong().size(13.5));
                                ui.label(
                                    RichText::new(&cur_target)
                                        .monospace()
                                        .size(18.0)
                                        .strong()
                                        .color(Color32::from_rgb(120, 220, 255)),
                                );

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button(RichText::new("❌ Cancel").size(11.5)).clicked() {
                                        action_cancel = true;
                                    }
                                });
                            });

                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(
                                    RichText::new(&cur_status)
                                        .size(12.0)
                                        .color(Color32::from_rgb(200, 220, 240)),
                                );
                            });
                        });
                    }

                    MatchState::Matched {
                        code,
                        is_host,
                        peer_ip: _,
                        game_launched,
                        ..
                    } => {
                        let matched_box = egui::Frame::group(ui.style())
                            .fill(Color32::from_rgb(18, 38, 28))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(80, 200, 120)))
                            .inner_margin(14.0);
                        let info_text = format!(
                            "(Code: {}, Role: {})",
                            code,
                            if *is_host { "Host" } else { "Guest" }
                        );
                        let is_launched = *game_launched;
                        matched_box.show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("✔ Connected to Friend!")
                                        .strong()
                                        .size(15.0)
                                        .color(Color32::from_rgb(100, 240, 140)),
                                );
                                ui.label(
                                    RichText::new(info_text)
                                        .size(12.5)
                                        .color(Color32::from_rgb(180, 220, 200)),
                                );

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button(RichText::new("❌ Disconnect").size(12.0)).clicked() {
                                        action_cancel = true;
                                    }
                                });
                            });

                            ui.add_space(8.0);

                            if !is_launched {
                                ui.columns(2, |cols| {
                                    let launch_btn = egui::Button::new(
                                        RichText::new("🚀 Launch Game (Co-op)")
                                            .size(14.0)
                                            .strong()
                                            .color(Color32::WHITE),
                                    )
                                    .fill(Color32::from_rgb(32, 140, 60))
                                    .min_size(Vec2::new(cols[0].available_width(), 38.0));

                                    if cols[0].add(launch_btn).clicked() {
                                        action_launch = true;
                                    }

                                    let attach_btn = egui::Button::new(
                                        RichText::new("🔗 Attach to Running Game")
                                            .size(13.5)
                                            .strong()
                                            .color(Color32::WHITE),
                                    )
                                    .fill(Color32::from_rgb(45, 95, 160))
                                    .min_size(Vec2::new(cols[1].available_width(), 38.0));

                                    if cols[1]
                                        .add(attach_btn)
                                        .on_hover_text(
                                            "Inject peer address & runtime hooks into an already-running splintercell3.exe (e.g. launched via Steam or Nucleus Co-op)",
                                        )
                                        .clicked()
                                    {
                                        action_attach_match = true;
                                    }
                                });
                            } else {
                                ui.horizontal(|ui| {
                                    ui.spinner();
                                    ui.label(
                                        RichText::new("✔ Game is running! Enter the in-game co-op lobby.")
                                            .size(13.0)
                                            .strong()
                                            .color(Color32::from_rgb(120, 230, 140)),
                                    );
                                });
                            }
                        });
                    }

                    MatchState::Failed { error } => {
                        let err_box = egui::Frame::group(ui.style())
                            .fill(Color32::from_rgb(42, 22, 22))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(220, 80, 80)))
                            .inner_margin(8.0);
                        let err_text = format!("⚠ Connection Failed: {}", error);
                        err_box.show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(err_text)
                                        .size(12.0)
                                        .color(Color32::from_rgb(255, 120, 120)),
                                );
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button(RichText::new("Back").size(11.5)).clicked() {
                                        action_cancel = true;
                                    }
                                });
                            });
                        });
                    }
                }

                if action_cancel {
                    self.cancel_matching();
                }
                if action_launch {
                    self.launch_match_game(ctx);
                }
                if action_attach_match {
                    self.attach_matched_game(ctx);
                }

                ui.add_space(4.0);

                // Advanced Server Settings Collapsible (Default Hidden)
                ui.collapsing("⚙ Advanced Server Settings", |ui| {
                    ui.add_space(2.0);
                    if let Some(root) = &self.resolved_root
                        && let Some(profile_dir) = crate::quicksave_persistence::find_scct_quicksave_profile_dir(root)
                    {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Persistent quick saves:").size(11.5));
                            ui.label(
                                RichText::new(format!("{}", profile_dir.display())).size(10.5),
                            );
                        });
                    }
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Server Address:").size(11.5));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.server_host)
                                .desired_width(180.0)
                                .hint_text("scct_coop.sholtrop.dev"),
                        );

                        ui.label(RichText::new("Connection Port (UDP):").size(11.5));
                        ui.add(egui::DragValue::new(&mut self.stun_port).range(1..=65535));

                        ui.label(RichText::new("Web Port (TCP):").size(11.5));
                        ui.add(egui::DragValue::new(&mut self.api_port).range(1..=65535));

                        if ui.button(RichText::new("Reset Defaults").size(11.0)).clicked() {
                            self.server_host = crate::stun::DEFAULT_SERVER_HOST.to_string();
                            self.stun_port = crate::stun::DEFAULT_STUN_PORT;
                            self.api_port = crate::stun::DEFAULT_API_PORT;
                        }
                    });
                });
            });

            ui.add_space(6.0);

            // =================================================================
            // Nucleus Co-op / External Launcher (Live Attach Mode)
            // =================================================================
            if self.installed_version.is_some() {
                let active_pids = self.active_pids_sorted();
                let is_watching = self.nucleus_watcher.is_some();
                let nucleus_frame = egui::Frame::group(ui.style())
                    .fill(Color32::from_rgb(20, 24, 30))
                    .inner_margin(10.0);

                let mut action_toggle_watch = false;
                let mut action_attach_now = false;

                nucleus_frame.show(ui, |ui| {
                    let header_text = if is_watching {
                        format!(
                            "🖥 Nucleus Co-op / Attach Mode — Watching (Attached: {})",
                            active_pids.len()
                        )
                    } else if !active_pids.is_empty() {
                        format!(
                            "🖥 Nucleus Co-op / Attach Mode (Attached PIDs: {:?})",
                            active_pids
                        )
                    } else {
                        "🖥 Nucleus Co-op / External Launcher (Attach Mode)".to_string()
                    };
                    egui::CollapsingHeader::new(RichText::new(header_text).size(13.5).strong())
                        .id_salt("nucleus_coop_attach_section")
                        .default_open(is_watching || !active_pids.is_empty())
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(
                                    "Use when Nucleus Co-op (or Steam) launches splintercell3.exe itself. Start 'Watch & Auto-Attach' before clicking Play in Nucleus, or click 'Attach Now' at the Main Menu.",
                                )
                                .size(11.5)
                                .color(Color32::from_rgb(180, 190, 205)),
                            );
                            ui.add_space(4.0);

                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("Nucleus Networking:")
                                        .size(11.5)
                                        .color(Color32::from_rgb(180, 180, 180)),
                                );
                                egui::ComboBox::from_id_salt("nucleus_net_mode_combo")
                                    .selected_text(self.nucleus_net_mode.label())
                                    .width(380.0)
                                    .show_ui(ui, |ui| {
                                        for choice in [
                                            NucleusNetModeChoice::BuiltInLoopbackPair,
                                            NucleusNetModeChoice::ExplicitPair,
                                            NucleusNetModeChoice::PreserveNucleusLan,
                                        ] {
                                            ui.selectable_value(
                                                &mut self.nucleus_net_mode,
                                                choice,
                                                choice.label(),
                                            );
                                        }
                                    });
                            });

                            if self.nucleus_net_mode == NucleusNetModeChoice::ExplicitPair {
                                ui.add_space(3.0);
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("Instance 1 IP:").size(11.5));
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.nucleus_pair_ip1)
                                            .desired_width(120.0)
                                            .hint_text("192.168.178.202"),
                                    );
                                    ui.label(RichText::new("Instance 2 IP:").size(11.5));
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.nucleus_pair_ip2)
                                            .desired_width(120.0)
                                            .hint_text("192.168.178.203"),
                                    );
                                    if self.available_local_ips.len() >= 2
                                        && ui
                                            .button(RichText::new("Use Detected NICs").size(11.0))
                                            .clicked()
                                    {
                                        self.nucleus_pair_ip1 =
                                            self.available_local_ips[0].to_string();
                                        self.nucleus_pair_ip2 =
                                            self.available_local_ips[1].to_string();
                                    }
                                });
                            }

                            ui.add_space(5.0);
                            ui.columns(2, |cols| {
                                let (watch_label, watch_fill) = if is_watching {
                                    (
                                        "⏹ Stop Watching (Nucleus Mode)",
                                        Color32::from_rgb(165, 60, 50),
                                    )
                                } else {
                                    (
                                        "👁 Watch & Auto-Attach (Nucleus Mode)",
                                        Color32::from_rgb(35, 100, 180),
                                    )
                                };
                                let watch_btn = egui::Button::new(
                                    RichText::new(watch_label)
                                        .size(12.5)
                                        .strong()
                                        .color(Color32::WHITE),
                                )
                                .fill(watch_fill)
                                .min_size(Vec2::new(cols[0].available_width(), 32.0));
                                if cols[0].add(watch_btn).clicked() {
                                    action_toggle_watch = true;
                                }

                                let attach_btn = egui::Button::new(
                                    RichText::new("🔗 Attach / Re-apply to Running Game(s)")
                                        .size(12.5)
                                        .strong()
                                        .color(Color32::WHITE),
                                )
                                .fill(Color32::from_rgb(45, 115, 85))
                                .min_size(Vec2::new(cols[1].available_width(), 32.0));
                                if cols[1].add(attach_btn).clicked() {
                                    action_attach_now = true;
                                }
                            });

                            if !active_pids.is_empty() {
                                ui.add_space(4.0);
                                let pid_list = active_pids
                                    .iter()
                                    .map(ToString::to_string)
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                ui.label(
                                    RichText::new(format!(
                                        "✔ Attached & monitoring splintercell3.exe PID(s): {}",
                                        pid_list
                                    ))
                                    .size(11.5)
                                    .color(Color32::from_rgb(120, 230, 140)),
                                );
                            }
                        });
                });

                if action_toggle_watch {
                    if is_watching {
                        self.stop_nucleus_watcher();
                        self.log_lines
                            .push(">>> [NUCLEUS] Stopped watching for new game launches.".to_string());
                    } else {
                        self.start_nucleus_watcher(ctx);
                    }
                }
                if action_attach_now {
                    self.attach_running_games_once(ctx);
                }

                ui.add_space(6.0);
            }

            if self.dev_mode {
                // =================================================================
                // Mod Feature & Debug Flags (28 Toggles across 6 Groups)
                // =================================================================
                let debug_frame = egui::Frame::group(ui.style())
                    .fill(Color32::from_rgb(20, 24, 30))
                    .inner_margin(8.0);
                debug_frame.show(ui, |ui| {
                    let flags_title = format!(
                        "🧪 Mod Feature & Debug Flags ({})",
                        self.patch_flags.summary_line()
                    );
                    egui::CollapsingHeader::new(RichText::new(flags_title).size(13.0).strong())
                        .id_salt("mod_feature_flags_header")
                        .default_open(true)
                        .show(ui, |ui| {
                            self.render_debug_patch_toggles(ui, ctx);
                        });
                });

                ui.add_space(6.0);
            }

            // =================================================================
            // Output Log Console
            // =================================================================
            ui.label(RichText::new("Log Output:").strong().size(12.5));
            ui.add_space(2.0);

            let terminal_frame = egui::Frame::canvas(ui.style())
                .fill(Color32::from_rgb(15, 17, 20))
                .inner_margin(8.0);

            terminal_frame.show(ui, |ui| {
                ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.set_min_height(ui.available_height());

                        if self.log_lines.is_empty() {
                            ui.label(
                                RichText::new("Ready. Select game folder and click 'Install Mod' above.")
                                    .monospace()
                                    .size(11.5)
                                    .color(Color32::from_rgb(100, 110, 120)),
                            );
                        } else {
                            for line in &self.log_lines {
                                let color = if line.starts_with("===") || line.starts_with("\n===") {
                                    Color32::from_rgb(100, 200, 255)
                                } else if line.contains("Success!")
                                    || line.starts_with(">>> Installation complete")
                                    || line.contains("successfully")
                                {
                                    Color32::from_rgb(100, 255, 130)
                                } else if line.contains("ERROR") || line.contains("Failed") {
                                    Color32::from_rgb(255, 100, 100)
                                } else if line.contains("[COOP]") {
                                    Color32::from_rgb(230, 230, 130)
                                } else if line.contains("[RESYNC]") {
                                    Color32::from_rgb(130, 240, 200)
                                } else if line.contains("[NET]")
                                    || line.contains("[HOST]")
                                    || line.contains("[JOIN]")
                                    || line.contains("[P2P]")
                                    || line.contains("[PATCHES]")
                                    || line.contains("[FLAGS]")
                                {
                                    Color32::from_rgb(140, 210, 255)
                                } else {
                                    Color32::from_rgb(210, 215, 220)
                                };

                                ui.label(RichText::new(line).monospace().size(11.5).color(color));
                            }
                        }
                    });
            });
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.stop_nucleus_watcher();
        self.stop_persistent_quick_saves();
        self.cancel_matching();
    }
}

impl Drop for PatcherApp {
    fn drop(&mut self) {
        self.stop_nucleus_watcher();
        self.stop_persistent_quick_saves();
        self.cancel_matching();
    }
}

fn run_host_match(
    server_host: String,
    stun_port: u16,
    api_port: u16,
    bind_ip: Option<std::net::Ipv4Addr>,
    tx: Sender<GuiEvent>,
    cancel_rx: Receiver<()>,
    ctx: egui::Context,
) {
    let _ = tx.send(GuiEvent::Log(
        "  [HOST] Initializing network session...".to_string(),
    ));
    ctx.request_repaint();

    // 1. Bind UDP sockets
    let (sock_disco, sock_game) = match crate::ip::bind_coop_udp_sockets(bind_ip) {
        Ok(socks) => socks,
        Err(e) => {
            let _ = tx.send(GuiEvent::MatchFailed(format!("{:#}", e)));
            ctx.request_repaint();
            return;
        }
    };

    let _ = tx.send(GuiEvent::Log(format!(
        "  [HOST] Connecting to online service ({}:{})...",
        server_host, stun_port
    )));
    ctx.request_repaint();

    // 2. Discover STUN public endpoints
    let mut disco_ext = match crate::stun::stun_query(&sock_disco, &server_host, stun_port) {
        Ok(addr) => addr,
        Err(e) => {
            let _ = tx.send(GuiEvent::MatchFailed(format!("Connection failed: {:#}", e)));
            ctx.request_repaint();
            return;
        }
    };

    let mut game_ext = match crate::stun::stun_query(&sock_game, &server_host, stun_port) {
        Ok(addr) => addr,
        Err(e) => {
            let _ = tx.send(GuiEvent::MatchFailed(format!(
                "Connection failed for game socket: {:#}",
                e
            )));
            ctx.request_repaint();
            return;
        }
    };

    let _ = tx.send(GuiEvent::Log(
        "  [HOST] Connection established with online service.".to_string(),
    ));
    ctx.request_repaint();

    // 3. Register with rendezvous server
    let my_local_ip = crate::ip::resolve_local_ip_for_coop(bind_ip, &server_host, api_port);

    let code = match crate::stun::register_with_server(
        &server_host,
        api_port,
        None,
        disco_ext,
        game_ext,
        my_local_ip,
    ) {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(GuiEvent::MatchFailed(format!(
                "Server registration failed: {:#}",
                e
            )));
            ctx.request_repaint();
            return;
        }
    };

    let _ = tx.send(GuiEvent::FriendCodeRegistered(code.clone()));
    let _ = tx.send(GuiEvent::Log(format!(
        "  [HOST] Friend Code created: {}. Share this with your friend!",
        code
    )));
    ctx.request_repaint();

    // 4. Poll for guest connection
    let mut wait_ticks: u32 = 0;
    loop {
        if cancel_rx.try_recv().is_ok() {
            let _ = tx.send(GuiEvent::Log(
                "  [HOST] Hosting session cancelled.".to_string(),
            ));
            ctx.request_repaint();
            return;
        }

        thread::sleep(Duration::from_millis(1000));

        if cancel_rx.try_recv().is_ok() {
            let _ = tx.send(GuiEvent::Log(
                "  [HOST] Hosting session cancelled.".to_string(),
            ));
            ctx.request_repaint();
            return;
        }

        match crate::stun::poll_server_for_peer(&server_host, api_port, &code, Some("host")) {
            Ok(crate::stun::PollPeerResult::Paired(peer_disco, peer_game, peer_local_ip)) => {
                let _ = tx.send(GuiEvent::MatchStatus(
                    "Friend connected! Establishing direct connection...".to_string(),
                ));
                let _ = tx.send(GuiEvent::Log(
                    "  [HOST] Friend connected! Establishing direct connection...".to_string(),
                ));
                ctx.request_repaint();

                let (peer_ip, peer_disco_port, peer_game_port, keepalive) = resolve_peer_connection(
                    "HOST",
                    &tx,
                    &ctx,
                    sock_disco,
                    sock_game,
                    disco_ext,
                    my_local_ip,
                    peer_disco,
                    peer_game,
                    peer_local_ip,
                );

                let _ = tx.send(GuiEvent::Matched {
                    code,
                    is_host: true,
                    peer_ip,
                    peer_disco_port,
                    peer_game_port,
                    keepalive,
                });
                let _ = tx.send(GuiEvent::Log(
                    "  [HOST] Direct connection ready! Click 'Launch Game (Co-op)' below."
                        .to_string(),
                ));
                ctx.request_repaint();
                return;
            }
            Ok(crate::stun::PollPeerResult::Waiting) => {
                wait_ticks = wait_ticks.wrapping_add(1);
                if wait_ticks.is_multiple_of(10)
                    && let (Ok(new_disco), Ok(new_game)) = (
                        crate::stun::stun_query(&sock_disco, &server_host, stun_port),
                        crate::stun::stun_query(&sock_game, &server_host, stun_port),
                    )
                    && (new_disco != disco_ext || new_game != game_ext)
                {
                    disco_ext = new_disco;
                    game_ext = new_game;
                    let _ = crate::stun::register_with_server(
                        &server_host,
                        api_port,
                        Some(code.clone()),
                        disco_ext,
                        game_ext,
                        my_local_ip,
                    );
                }
            }
            Ok(crate::stun::PollPeerResult::Disconnected(reason)) => {
                let _ = tx.send(GuiEvent::MatchFailed(format!(
                    "Hosting session ended: {}",
                    reason
                )));
                ctx.request_repaint();
                return;
            }
            Err(e) => {
                let _ = tx.send(GuiEvent::MatchFailed(format!(
                    "Server polling error: {:#}",
                    e
                )));
                ctx.request_repaint();
                return;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_peer_connection(
    role_tag: &str,
    tx: &Sender<GuiEvent>,
    ctx: &egui::Context,
    sock_disco: std::net::UdpSocket,
    sock_game: std::net::UdpSocket,
    disco_ext: std::net::SocketAddr,
    my_local_ip: Option<Ipv4Addr>,
    peer_disco: std::net::SocketAddr,
    peer_game: std::net::SocketAddr,
    peer_local_ip: Option<Ipv4Addr>,
) -> (Ipv4Addr, u16, u16, Option<KeepaliveHandle>) {
    // Simultaneous UDP hole punch
    crate::stun::punch_udp_holes(&sock_disco, &sock_game, peer_disco, peer_game);

    let (ip, peer_disco_port, peer_game_port, is_lan) = crate::stun::resolve_peer_endpoint(
        disco_ext,
        my_local_ip,
        peer_disco,
        peer_game,
        peer_local_ip,
    );

    if is_lan {
        let _ = tx.send(GuiEvent::Log(format!(
            "  [{}] Detected friend on local network (LAN)! Connecting directly...",
            role_tag
        )));
        let lan_peer_disco =
            std::net::SocketAddr::new(std::net::IpAddr::V4(ip), crate::net::DISCOVERY_PORT);
        let lan_peer_game =
            std::net::SocketAddr::new(std::net::IpAddr::V4(ip), crate::net::GAME_PORT);
        let keepalive = spawn_punch_keepalive(
            sock_disco,
            sock_game,
            lan_peer_disco,
            lan_peer_game,
            tx.clone(),
            ctx.clone(),
        );
        return (
            ip,
            crate::net::DISCOVERY_PORT,
            crate::net::GAME_PORT,
            Some(keepalive),
        );
    }

    let _ = tx.send(GuiEvent::Log(format!(
        "  [{}] Connecting to friend across the Internet...",
        role_tag
    )));
    let keepalive = spawn_punch_keepalive(
        sock_disco,
        sock_game,
        peer_disco,
        peer_game,
        tx.clone(),
        ctx.clone(),
    );
    (ip, peer_disco_port, peer_game_port, Some(keepalive))
}

fn run_join_match(
    server_host: String,
    stun_port: u16,
    api_port: u16,
    bind_ip: Option<std::net::Ipv4Addr>,
    target_code: String,
    tx: Sender<GuiEvent>,
    ctx: egui::Context,
) {
    let _ = tx.send(GuiEvent::Log(format!(
        "  [JOIN] Connecting to friend with code '{}'...",
        target_code
    )));
    ctx.request_repaint();

    // 1. Bind UDP sockets
    let (sock_disco, sock_game) = match crate::ip::bind_coop_udp_sockets(bind_ip) {
        Ok(socks) => socks,
        Err(e) => {
            let _ = tx.send(GuiEvent::MatchFailed(format!("{:#}", e)));
            ctx.request_repaint();
            return;
        }
    };

    let _ = tx.send(GuiEvent::Log(format!(
        "  [JOIN] Connecting to online service ({}:{})...",
        server_host, stun_port
    )));
    ctx.request_repaint();

    // 2. Discover STUN public endpoints
    let disco_ext = match crate::stun::stun_query(&sock_disco, &server_host, stun_port) {
        Ok(addr) => addr,
        Err(e) => {
            let _ = tx.send(GuiEvent::MatchFailed(format!("Connection failed: {:#}", e)));
            ctx.request_repaint();
            return;
        }
    };

    let game_ext = match crate::stun::stun_query(&sock_game, &server_host, stun_port) {
        Ok(addr) => addr,
        Err(e) => {
            let _ = tx.send(GuiEvent::MatchFailed(format!(
                "Connection failed for game socket: {:#}",
                e
            )));
            ctx.request_repaint();
            return;
        }
    };

    let _ = tx.send(GuiEvent::MatchStatus(
        "Exchanging connection details with host...".to_string(),
    ));
    let _ = tx.send(GuiEvent::Log(
        "  [JOIN] Exchanging connection details with host...".to_string(),
    ));
    ctx.request_repaint();

    let my_local_ip = crate::ip::resolve_local_ip_for_coop(bind_ip, &server_host, api_port);

    // 3. Connect via rendezvous server
    let (peer_disco, peer_game, peer_local_ip) = match crate::stun::join_with_server(
        &server_host,
        api_port,
        &target_code,
        disco_ext,
        game_ext,
        my_local_ip,
    ) {
        Ok(triple) => triple,
        Err(e) => {
            let _ = tx.send(GuiEvent::MatchFailed(format!(
                "Failed to connect with friend code '{}': {:#}",
                target_code, e
            )));
            ctx.request_repaint();
            return;
        }
    };

    let _ = tx.send(GuiEvent::MatchStatus(
        "Host found! Establishing connection...".to_string(),
    ));
    let _ = tx.send(GuiEvent::Log(
        "  [JOIN] Connected to friend! Establishing direct connection...".to_string(),
    ));
    ctx.request_repaint();

    // 4. Simultaneous UDP hole punch + keepalive handoff
    let (peer_ip, peer_disco_port, peer_game_port, keepalive) = resolve_peer_connection(
        "JOIN",
        &tx,
        &ctx,
        sock_disco,
        sock_game,
        disco_ext,
        my_local_ip,
        peer_disco,
        peer_game,
        peer_local_ip,
    );

    let _ = tx.send(GuiEvent::Matched {
        code: target_code,
        is_host: false,
        peer_ip,
        peer_disco_port,
        peer_game_port,
        keepalive,
    });
    let _ = tx.send(GuiEvent::Log(
        "  [JOIN] Direct connection ready! Click 'Launch Game (Co-op)' below.".to_string(),
    ));
    ctx.request_repaint();
}

fn spawn_game_monitor(
    mut game_proc: crate::launcher::GameProcess,
    tx: Sender<GuiEvent>,
    ctx_clone: egui::Context,
    root_clone: PathBuf,
) {
    let pid = game_proc.pid;
    let role_str = game_proc.peer_role.as_str();
    let resync_active = game_proc.resync_coord.is_some();
    thread::spawn(move || {
        let mut desync_dumped = false;
        let mut trace_notified = false;
        loop {
            let alive = game_proc.is_alive();
            let poll =
                game_proc.poll_monitor_once(&root_clone, &mut desync_dumped, &mut trace_notified);
            if let Some(trace_path) = poll.trace_started {
                let _ = tx.send(GuiEvent::Log(format!(
                    ">>> [TRACE] Recording startup sync/tick trace ({}) to: {}",
                    role_str,
                    trace_path.display()
                )));
                ctx_clone.request_repaint();
            }
            if !poll.resync_logs.is_empty() {
                for line in poll.resync_logs {
                    let _ = tx.send(GuiEvent::Log(format!(">>> {}", line)));
                }
                ctx_clone.request_repaint();
            }
            if let Some(desync_res) = poll.desync {
                match desync_res {
                    Ok(report) => {
                        let _ = tx.send(GuiEvent::DesyncDetected(report));
                    }
                    Err(e) => {
                        let _ = tx.send(GuiEvent::DesyncDumpFailed(format!("{:#}", e)));
                    }
                }
                ctx_clone.request_repaint();
            }
            if !alive {
                break;
            }
            let sleep_ms = if resync_active { 10 } else { 100 };
            thread::sleep(std::time::Duration::from_millis(sleep_ms));
        }
        game_proc.wait_for_exit();
        let _ = tx.send(GuiEvent::GameExited(pid));
        ctx_clone.request_repaint();
    });
}

/// Centers a rectangular RGBA icon inside a square buffer using its border pixel so
/// Windows taskbar/titlebar icon scaling does not squash non-square logos.
fn pad_icon_to_square(icon: egui::IconData) -> egui::IconData {
    let (w, h) = (icon.width as usize, icon.height as usize);
    if w == 0 || h == 0 || w == h || icon.rgba.len() != w * h * 4 {
        return icon;
    }

    let side = w.max(h);
    let fill = [icon.rgba[0], icon.rgba[1], icon.rgba[2], icon.rgba[3]];
    let mut padded = fill.repeat(side * side);

    let x_off = (side - w) / 2;
    let y_off = (side - h) / 2;
    for (row, src_row) in icon.rgba.chunks_exact(w * 4).enumerate() {
        let dst_start = ((y_off + row) * side + x_off) * 4;
        padded[dst_start..dst_start + w * 4].copy_from_slice(src_row);
    }

    egui::IconData {
        rgba: padded,
        width: side as u32,
        height: side as u32,
    }
}

fn load_app_icon() -> Option<egui::IconData> {
    eframe::icon_data::from_png_bytes(include_bytes!("../../images/scct_ec_logo.png"))
        .ok()
        .map(pad_icon_to_square)
}

pub fn run_gui(
    explicit_dir: Option<PathBuf>,
    initial_bind_ip: Option<std::net::Ipv4Addr>,
    initial_auto_resync: bool,
    dev_mode: bool,
) -> eframe::Result {
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([780.0, 800.0])
        .with_min_inner_size([540.0, 480.0])
        .with_title("SCCT Coop Mod Installer & Online Launcher");
    if let Some(icon) = load_app_icon() {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }

    let options = eframe::NativeOptions {
        viewport,
        hardware_acceleration: eframe::HardwareAcceleration::Preferred,
        ..Default::default()
    };

    eframe::run_native(
        "SCCT Coop Mod Installer & Online Launcher",
        options,
        Box::new(move |cc| {
            Ok(Box::new(PatcherApp::new(
                cc,
                explicit_dir,
                initial_bind_ip,
                initial_auto_resync,
                dev_mode,
            )))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::{InstallState, PatcherApp, install_button_label, load_app_icon};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn embedded_app_icon_loads_as_square_rgba() {
        let icon = load_app_icon().expect("scct_ec_logo.png should decode");
        assert!(icon.width > 0);
        assert_eq!(icon.width, icon.height);
        assert_eq!(icon.rgba.len(), (icon.width * icon.height * 4) as usize);
    }

    fn make_fake_root(label: &str, with_version_file: bool) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "scct-gui-{label}-{}-{nanos}",
            std::process::id()
        ));
        let sys = root.join("System");
        std::fs::create_dir_all(&sys).unwrap();
        std::fs::write(sys.join("splintercell3.exe"), b"MZ").unwrap();
        if with_version_file {
            crate::patcher::write_version_file(&root).unwrap();
        }
        root
    }

    #[test]
    fn uninstall_done_resets_state_to_idle_and_shows_install_button() {
        let root = make_fake_root("uninstall", true);
        let mut app = PatcherApp::init_state(Some(root.clone()), None, false, false, false);
        assert!(app.installed_version.is_some());

        app.state = InstallState::Uninstalling;
        crate::patcher::remove_version_file(&root).unwrap();
        app.handle_uninstall_done(&root, true);

        assert_eq!(app.installed_version, None);
        assert_eq!(app.state, InstallState::Idle);
        assert_eq!(install_button_label(&app.state), "🎮 Install Mod");
        assert!(!install_button_label(&app.state).contains("Installed Successfully"));

        drop(app);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn switching_game_root_and_stale_install_events_do_not_leave_stale_state() {
        let installed_root = make_fake_root("installed", true);
        let vanilla_root = make_fake_root("vanilla", false);

        let mut app = PatcherApp::init_state(None, None, false, false, false);
        app.set_game_root(installed_root.clone());
        app.state = InstallState::Failed;

        // Switching to another game root resets stale state cleanly.
        app.set_game_root(vanilla_root.clone());
        assert_eq!(app.state, InstallState::Idle);
        assert_eq!(app.installed_version, None);

        // Stale completion for the old root must not claim vanilla_root is installed.
        app.state = InstallState::Installing;
        app.handle_install_done(&installed_root, true);
        assert_eq!(app.installed_version, None);
        assert_eq!(app.state, InstallState::Idle);

        // If ok=true yet version file is still absent on active root, do not report success.
        app.handle_install_done(&vanilla_root, true);
        assert_eq!(app.installed_version, None);
        assert_eq!(app.state, InstallState::Failed);

        drop(app);
        std::fs::remove_dir_all(installed_root).unwrap();
        std::fs::remove_dir_all(vanilla_root).unwrap();
    }

    #[test]
    fn nucleus_net_mode_selection_and_multi_pid_tracking() {
        let mut app = PatcherApp::init_state(None, None, false, false, false);
        assert_eq!(
            app.selected_nucleus_net_mode().unwrap(),
            crate::launcher::NucleusNetMode::BuiltInLoopbackPair
        );

        app.nucleus_net_mode = super::NucleusNetModeChoice::PreserveNucleusLan;
        assert_eq!(
            app.selected_nucleus_net_mode().unwrap(),
            crate::launcher::NucleusNetMode::PreserveNucleusLan
        );

        app.nucleus_net_mode = super::NucleusNetModeChoice::ExplicitPair;
        app.nucleus_pair_ip1 = "192.168.178.202".to_string();
        app.nucleus_pair_ip2 = "192.168.178.203".to_string();
        assert_eq!(
            app.selected_nucleus_net_mode().unwrap(),
            crate::launcher::NucleusNetMode::ExplicitPair(
                std::net::Ipv4Addr::new(192, 168, 178, 202),
                std::net::Ipv4Addr::new(192, 168, 178, 203),
            )
        );

        app.nucleus_pair_ip2 = "192.168.178.202".to_string();
        assert!(app.selected_nucleus_net_mode().is_err());

        {
            let mut set = app.active_game_pids.lock().unwrap();
            set.insert(9002);
            set.insert(4001);
        }
        assert_eq!(app.active_pids_sorted(), vec![4001, 9002]);
    }
}
