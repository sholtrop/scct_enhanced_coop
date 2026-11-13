use crate::quicksave_persistence::PersistentQuickSaveHandle;
use eframe::egui::{self, Color32, RichText, ScrollArea, Vec2};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
enum InstallState {
    Idle,
    Installing,
    Uninstalling,
    Success,
    Failed,
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
    InstallDone(bool),
    UninstallDone(bool),
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
    GameExited(u32),
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

    // Running game process
    running_game_pid: Option<u32>,

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

    // Modular patch flags & optional gameplay tweaks
    pub flags: Vec<crate::flags::FlagState>,
}

impl PatcherApp {
    pub fn new(
        cc: &eframe::CreationContext,
        explicit_dir: Option<PathBuf>,
        initial_bind_ip: Option<std::net::Ipv4Addr>,
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

        let (sender, receiver) = channel();
        let initial_bind_ip = initial_bind_ip.filter(|ip| !ip.is_unspecified());

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
            running_game_pid: None,
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
            available_local_ips: crate::ip::get_all_local_ips(),
            selected_bind_ip: initial_bind_ip,
            flags: crate::flags::default_flag_states(),
        };

        let detected = crate::patcher::auto_detect_game_roots();
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
        self.installed_version = crate::patcher::get_installed_version(&root);
        self.flags = crate::flags::load_flag_states(&root);

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

        if self.persistent_quick_saves.is_none() {
            self.persistent_quick_saves = Some(
                crate::quicksave_persistence::spawn_quicksave_persistence(root),
            );
        }
    }

    fn check_manual_path_input(&mut self) {
        let trimmed = self.game_dir_input.trim();
        if trimmed.is_empty() {
            self.resolved_root = None;
            self.installed_version = None;
            self.detection_msg = "Please select or enter the Chaos Theory game folder.".to_string();
            return;
        }

        let path = Path::new(trimmed);
        if let Some(valid) = crate::patcher::validate_game_root(path) {
            if self.resolved_root.as_ref() != Some(&valid) {
                self.set_game_root(valid);
            }
        } else {
            self.resolved_root = None;
            self.installed_version = None;
            self.detection_msg =
                "System/splintercell3.exe not found in this folder. Please verify the path."
                    .to_string();
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

    fn stop_persistent_quick_saves(&mut self) {
        if let Some(mut quicksaves) = self.persistent_quick_saves.take() {
            quicksaves.stop();
        }
    }

    fn restore_quick_saves_before_launch(&mut self, game_root: &Path) {
        if let Err(error) = crate::quicksave_persistence::restore_latest_quick_saves(game_root) {
            self.log_lines.push(format!(
                ">>> [QUICKSAVE] Could not restore previous co-op quick saves: {:#}",
                error
            ));
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

        let exe_bak_path = sys_dir.join("splintercell3.exe.bak");
        if let Err(e) = crate::net::update_direct_target_in_exe(
            &exe_path,
            &exe_bak_path,
            Some(peer_ip),
            peer_disco_port,
            peer_game_port,
        ) {
            self.log_lines.push(format!(
                ">>> [LAUNCH ERROR] Could not prepare game executable (make sure Chaos Theory is closed first): {:#}",
                e
            ));
            ctx.request_repaint();
            return;
        }

        if let Err(e) = crate::flags::sync_all_flags(&root, &self.flags) {
            self.log_lines
                .push(format!(">>> [WARNING] Could not sync patch flags: {:#}", e));
        }

        self.restore_quick_saves_before_launch(&root);

        match crate::launcher::launch_game(
            &exe_path,
            &root,
            Some(peer_ip),
            peer_disco_port,
            peer_game_port,
            self.selected_bind_ip,
        ) {
            Ok(proc) => {
                let pid = proc.pid;
                self.running_game_pid = Some(pid);
                if let MatchState::Matched {
                    ref mut game_launched,
                    ..
                } = self.match_state
                {
                    *game_launched = true;
                }
                let tx = self.sender.clone();
                let ctx_clone = ctx.clone();
                thread::spawn(move || {
                    proc.wait_for_exit();
                    let _ = tx.send(GuiEvent::GameExited(pid));
                    ctx_clone.request_repaint();
                });
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

        let exe_bak_path = sys_dir.join("splintercell3.exe.bak");
        if let Err(e) = crate::net::update_direct_ip_in_exe(&exe_path, &exe_bak_path, None) {
            self.log_lines.push(format!(
                ">>> [LAUNCH ERROR] Could not prepare game executable (make sure Chaos Theory is closed first): {:#}",
                e
            ));
            ctx.request_repaint();
            return;
        }

        if let Err(e) = crate::flags::sync_all_flags(&root, &self.flags) {
            self.log_lines
                .push(format!(">>> [WARNING] Could not sync patch flags: {:#}", e));
        }

        self.restore_quick_saves_before_launch(&root);

        match crate::launcher::launch_game(
            &exe_path,
            &root,
            None,
            crate::net::DISCOVERY_PORT,
            crate::net::GAME_PORT,
            self.selected_bind_ip,
        ) {
            Ok(proc) => {
                let pid = proc.pid;
                self.running_game_pid = Some(pid);
                let tx = self.sender.clone();
                let ctx_clone = ctx.clone();
                thread::spawn(move || {
                    proc.wait_for_exit();
                    let _ = tx.send(GuiEvent::GameExited(pid));
                    ctx_clone.request_repaint();
                });
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
                GuiEvent::InstallDone(ok) => {
                    self.state = if ok {
                        InstallState::Success
                    } else {
                        InstallState::Failed
                    };
                    if ok && let Some(ref root) = self.resolved_root {
                        self.installed_version = crate::patcher::get_installed_version(root);
                        self.detection_msg = format!(
                            "Game detected: {} (Co-op Mod v{} installed)",
                            root.display(),
                            self.installed_version
                                .as_deref()
                                .unwrap_or(crate::patcher::MOD_VERSION)
                        );
                    }
                }
                GuiEvent::UninstallDone(ok) => {
                    self.state = if ok {
                        InstallState::Success
                    } else {
                        InstallState::Failed
                    };
                    if ok {
                        self.installed_version = None;
                        if let Some(ref root) = self.resolved_root {
                            self.detection_msg =
                                format!("Game detected: {} (Vanilla)", root.display());
                        }
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
                GuiEvent::GameExited(pid) => {
                    if self.running_game_pid == Some(pid) {
                        self.running_game_pid = None;
                    }
                    self.log_lines.push(format!(
                        ">>> Splinter Cell Chaos Theory (PID: {}) has exited.",
                        pid
                    ));
                    if let MatchState::Matched { ref code, .. } = self.match_state {
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
                                self.resolved_root = None;
                                self.detection_msg =
                                    "System/splintercell3.exe not found in selected folder."
                                        .to_string();
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
            let is_busy = self.state == InstallState::Installing || self.state == InstallState::Uninstalling;
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
                        self.state = InstallState::Installing;
                        self.log_lines.clear();

                        let tx = self.sender.clone();
                        let tx_status = self.sender.clone();
                        let ctx_clone = ctx.clone();
                        let root = self.resolved_root.clone().unwrap();
                        let flags = self.flags.clone();

                        crate::patcher::set_log_sink(move |msg| {
                            let _ = tx.send(GuiEvent::Log(msg.to_string()));
                            ctx_clone.request_repaint();
                        });

                        let ctx_finish = ctx.clone();
                        thread::spawn(move || {
                            let res = crate::patcher::apply_all(&root, false, &flags);
                            match res {
                                Ok(_) => {
                                    let _ = tx_status.send(GuiEvent::Log("\n>>> Reinstallation complete! All coop missions and network fixes re-applied.".to_string()));
                                    let _ = tx_status.send(GuiEvent::InstallDone(true));
                                }
                                Err(e) => {
                                    let _ = tx_status.send(GuiEvent::Log(format!("\n>>> ERROR: {:#}", e)));
                                    let _ = tx_status.send(GuiEvent::InstallDone(false));
                                }
                            }
                            crate::patcher::clear_log_sink();
                            ctx_finish.request_repaint();
                        });
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
                                    let _ = tx_status.send(GuiEvent::UninstallDone(true));
                                }
                                Err(e) => {
                                    let _ = tx_status.send(GuiEvent::Log(format!("\n>>> ERROR: {:#}", e)));
                                    let _ = tx_status.send(GuiEvent::UninstallDone(false));
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

                let button_text = match self.state {
                    InstallState::Idle => "🎮 Install Mod",
                    InstallState::Installing => "Installing Mod... (Please wait)",
                    InstallState::Uninstalling => "Uninstalling Mod... (Please wait)",
                    InstallState::Success => "✔ Mod Installed Successfully",
                    InstallState::Failed => "❌ Installation Failed (Click to Retry)",
                };

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
                    self.state = InstallState::Installing;
                    self.log_lines.clear();

                    let tx = self.sender.clone();
                    let tx_status = self.sender.clone();
                    let ctx_clone = ctx.clone();
                    let root = self.resolved_root.clone().unwrap();
                    let flags = self.flags.clone();

                    crate::patcher::set_log_sink(move |msg| {
                        let _ = tx.send(GuiEvent::Log(msg.to_string()));
                        ctx_clone.request_repaint();
                    });

                    let ctx_finish = ctx.clone();
                    thread::spawn(move || {
                        let res = crate::patcher::apply_all(&root, false, &flags);
                        match res {
                            Ok(_) => {
                                let _ = tx_status.send(GuiEvent::Log("\n>>> Installation complete! You can now use the Friend Code section below to play online with friends.".to_string()));
                                let _ = tx_status.send(GuiEvent::InstallDone(true));
                            }
                            Err(e) => {
                                let _ = tx_status.send(GuiEvent::Log(format!("\n>>> ERROR: {:#}", e)));
                                let _ = tx_status.send(GuiEvent::InstallDone(false));
                            }
                        }
                        crate::patcher::clear_log_sink();
                        ctx_finish.request_repaint();
                    });
                }
            }

            // Optional Patch Flags & Gameplay Tweaks (List of Checkboxes)
            if self.resolved_root.is_some() && !self.flags.is_empty() {
                ui.add_space(8.0);
                egui::Frame::NONE
                    .fill(Color32::from_rgb(26, 30, 38))
                    .inner_margin(8.0)
                    .corner_radius(4.0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("Optional Patch Flags")
                                    .strong()
                                    .size(12.5)
                                    .color(Color32::from_rgb(220, 225, 235)),
                            );
                            ui.label(
                                RichText::new("(Experimental gameplay fixes for splintercell3.exe)")
                                    .size(11.0)
                                    .color(Color32::from_rgb(140, 145, 155)),
                            );
                        });
                        ui.add_space(4.0);

                        let mut toggle_action: Option<(usize, bool)> = None;
                        for (idx, flag) in self.flags.iter_mut().enumerate() {
                            ui.horizontal(|ui| {
                                let mut checked = flag.enabled;
                                let cb = egui::Checkbox::new(
                                    &mut checked,
                                    RichText::new(flag.def.name).size(12.0),
                                );
                                let resp = ui.add_enabled(can_click, cb);
                                if flag.def.experimental {
                                    ui.colored_label(
                                        Color32::from_rgb(255, 160, 80),
                                        "⚠️ EXPERIMENTAL",
                                    );
                                }
                                if resp.changed() {
                                    toggle_action = Some((idx, checked));
                                }
                            });
                            ui.indent(flag.def.id, |ui| {
                                ui.label(
                                    RichText::new(flag.def.description)
                                        .size(10.5)
                                        .color(Color32::from_rgb(150, 155, 165)),
                                );
                            });
                            ui.add_space(2.0);
                        }

                        if let Some((idx, new_val)) = toggle_action {
                            self.flags[idx].enabled = new_val;
                            if let Some(ref root) = self.resolved_root.clone() {
                                if self.installed_version.is_some() {
                                    let flag_id = self.flags[idx].def.id;
                                    let flag_name = self.flags[idx].def.name;
                                    match crate::flags::set_flag_applied(&root, flag_id, new_val) {
                                        Ok(()) => {
                                            let act = if new_val { "Enabled" } else { "Disabled" };
                                            self.log_lines.push(format!(">>> [FLAG] {} {}", act, flag_name));
                                        }
                                        Err(e) => {
                                            self.flags[idx].enabled = !new_val;
                                            self.log_lines.push(format!(">>> [ERROR] Failed to toggle flag {}: {:#}", flag_name, e));
                                        }
                                    }
                                }
                            }
                        }
                    });
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
                                let launch_btn = egui::Button::new(
                                    RichText::new("🚀 Launch Game (Co-op)")
                                        .size(14.5)
                                        .strong()
                                        .color(Color32::WHITE),
                                )
                                .fill(Color32::from_rgb(32, 140, 60))
                                .min_size(Vec2::new(ui.available_width(), 38.0));

                                if ui.add(launch_btn).clicked() {
                                    action_launch = true;
                                }
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
                                } else if line.contains("[NET]")
                                    || line.contains("[HOST]")
                                    || line.contains("[JOIN]")
                                    || line.contains("[P2P]")
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
        self.stop_persistent_quick_saves();
        self.cancel_matching();
    }
}

impl Drop for PatcherApp {
    fn drop(&mut self) {
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

pub fn run_gui(
    explicit_dir: Option<PathBuf>,
    initial_bind_ip: Option<std::net::Ipv4Addr>,
) -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([780.0, 680.0])
            .with_min_inner_size([540.0, 480.0])
            .with_title("SCCT Coop Mod Installer & Online Launcher"),
        hardware_acceleration: eframe::HardwareAcceleration::Preferred,
        ..Default::default()
    };

    eframe::run_native(
        "SCCT Coop Mod Installer & Online Launcher",
        options,
        Box::new(move |cc| Ok(Box::new(PatcherApp::new(cc, explicit_dir, initial_bind_ip)))),
    )
}
