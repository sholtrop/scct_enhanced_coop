use eframe::egui::{self, Color32, RichText, ScrollArea, Vec2};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
enum InstallState {
    Idle,
    Running,
    Success,
    Failed,
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
        sock_disco: std::net::UdpSocket,
        sock_game: std::net::UdpSocket,
        game_launched: bool,
    },
    Failed {
        error: String,
    },
}

pub enum GuiEvent {
    Log(String),
    InstallDone(bool),
    PublicIp(Result<Ipv4Addr, String>),
    FriendCodeRegistered(String),
    MatchStatus(String),
    Matched {
        code: String,
        is_host: bool,
        peer_ip: Ipv4Addr,
        sock_disco: std::net::UdpSocket,
        sock_game: std::net::UdpSocket,
    },
    MatchFailed(String),
}

pub struct PatcherApp {
    game_dir_input: String,
    resolved_root: Option<PathBuf>,
    detected_roots: Vec<PathBuf>,
    detection_msg: String,
    state: InstallState,
    log_lines: Vec<String>,
    receiver: Receiver<GuiEvent>,
    sender: Sender<GuiEvent>,

    // Public IP state
    public_ip: Option<Ipv4Addr>,
    fetching_ip: bool,
    ip_fetch_err: Option<String>,

    // Friend Code & STUN Matchmaking
    match_state: MatchState,
    guest_code_input: String,
    cancel_tx: Option<Sender<()>>,

    // Advanced Server Settings
    server_host: String,
    stun_port: u16,
    api_port: u16,
}

impl PatcherApp {
    pub fn new(_cc: &eframe::CreationContext, explicit_dir: Option<PathBuf>) -> Self {
        let (sender, receiver) = channel();

        let mut app = Self {
            game_dir_input: String::new(),
            resolved_root: None,
            detected_roots: Vec::new(),
            detection_msg: String::new(),
            state: InstallState::Idle,
            log_lines: Vec::new(),
            receiver,
            sender,
            public_ip: None,
            fetching_ip: true,
            ip_fetch_err: None,
            match_state: MatchState::Idle,
            guest_code_input: String::new(),
            cancel_tx: None,
            server_host: crate::stun::DEFAULT_SERVER_HOST.to_string(),
            stun_port: crate::stun::DEFAULT_STUN_PORT,
            api_port: crate::stun::DEFAULT_API_PORT,
        };

        // Automatically fetch public IP in background on startup
        let tx_ip = app.sender.clone();
        thread::spawn(move || {
            match crate::ip::fetch_public_ip() {
                Ok(ip) => {
                    let _ = tx_ip.send(GuiEvent::PublicIp(Ok(ip)));
                }
                Err(e) => {
                    let _ = tx_ip.send(GuiEvent::PublicIp(Err(e.to_string())));
                }
            }
        });

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
        self.detection_msg = format!("Game detected: {}", root.display());
        self.resolved_root = Some(root);
    }

    fn check_manual_path_input(&mut self) {
        let trimmed = self.game_dir_input.trim();
        if trimmed.is_empty() {
            self.resolved_root = None;
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
            self.detection_msg =
                "System/splintercell3.exe not found in this folder. Please verify the path."
                    .to_string();
        }
    }

    fn cancel_matching(&mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(());
        }
        self.match_state = MatchState::Idle;
    }

    fn start_hosting(&mut self, ctx: &egui::Context) {
        self.cancel_matching();
        let (cancel_tx, cancel_rx) = channel();
        self.cancel_tx = Some(cancel_tx);
        self.match_state = MatchState::Hosting {
            code: "Connecting...".to_string(),
            status_text: "Discovering NAT endpoints via STUN server...".to_string(),
        };

        let server_host = self.server_host.clone();
        let stun_port = self.stun_port;
        let api_port = self.api_port;
        let tx = self.sender.clone();
        let ctx_clone = ctx.clone();

        thread::spawn(move || {
            run_host_match(server_host, stun_port, api_port, tx, cancel_rx, ctx_clone);
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
        self.match_state = MatchState::Joining {
            target_code: code.clone(),
            status_text: format!("Contacting server to match code '{}'...", code),
        };

        let server_host = self.server_host.clone();
        let stun_port = self.stun_port;
        let api_port = self.api_port;
        let tx = self.sender.clone();
        let ctx_clone = ctx.clone();

        thread::spawn(move || {
            run_join_match(server_host, stun_port, api_port, code, tx, ctx_clone);
        });
    }

    fn launch_match_game(&mut self, ctx: &egui::Context) {
        if let MatchState::Matched {
            code: _,
            is_host,
            peer_ip,
            ref sock_disco,
            ref sock_game,
            ref mut game_launched,
        } = self.match_state
        {
            if *game_launched {
                self.log_lines
                    .push("  [LAUNCH] Game already running for this session!".to_string());
                return;
            }

            let Some(ref root) = self.resolved_root else {
                self.log_lines
                    .push("  [LAUNCH] ERROR: Game folder not selected!".to_string());
                return;
            };

            let sys_dir = crate::patcher::find_child_ci(root, "System");
            let exe_path = crate::patcher::find_child_ci(&sys_dir, "splintercell3.exe");
            if !exe_path.exists() {
                self.log_lines.push(format!(
                    "  [LAUNCH] ERROR: Executable not found at {}",
                    exe_path.display()
                ));
                return;
            }

            let ini_path = sys_dir.join("direct_ip.ini");
            let _ = crate::net::save_direct_ip_ini(&ini_path, Some(peer_ip));

            match crate::launcher::launch_game_with_inherited_sockets(
                &exe_path,
                root,
                sock_disco,
                sock_game,
                Some(peer_ip),
            ) {
                Ok(pid) => {
                    *game_launched = true;
                    self.log_lines.push(format!(
                        ">>> Chaos Theory Coop launched successfully (PID: {})!",
                        pid
                    ));
                    self.log_lines.push(
                        ">>> Ingested primed UDP sockets (9100 & 9103) with STUN NAT traversal."
                            .to_string(),
                    );
                    if is_host {
                        self.log_lines.push(
                            ">>> [HOST]: In game main menu, select Coop -> Host Game to create the room."
                                .to_string(),
                        );
                    } else {
                        self.log_lines.push(format!(
                            ">>> [GUEST]: In game main menu, select Coop -> click 'Online' to join Host ({}).",
                            peer_ip
                        ));
                    }
                }
                Err(e) => {
                    self.log_lines
                        .push(format!(">>> [LAUNCH ERROR] Failed to launch game: {:#}", e));
                }
            }
            ctx.request_repaint();
        }
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
                }
                GuiEvent::PublicIp(res) => {
                    self.fetching_ip = false;
                    match res {
                        Ok(ip) => self.public_ip = Some(ip),
                        Err(err) => self.ip_fetch_err = Some(err),
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
                    sock_disco,
                    sock_game,
                } => {
                    self.match_state = MatchState::Matched {
                        code,
                        is_host,
                        peer_ip,
                        sock_disco,
                        sock_game,
                        game_launched: false,
                    };
                }
                GuiEvent::MatchFailed(error) => {
                    self.match_state = MatchState::Failed { error };
                }
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(4.0);

            // Title
            ui.heading(
                RichText::new("Splinter Cell: Chaos Theory — Coop Mod")
                    .strong()
                    .size(20.0),
            );
            ui.label(
                RichText::new(
                    "Convert all 11 Single Player missions to Coop + STUN Zero-Config P2P Online",
                )
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
            // Main Action Button ("Install Mod")
            // =================================================================
            let can_click = self.state != InstallState::Running && self.resolved_root.is_some();
            let button_text = match self.state {
                InstallState::Idle => "Install Mod",
                InstallState::Running => "Installing Mod... (Please wait)",
                InstallState::Success => "✔ Mod Installed Successfully (Click to Reinstall)",
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
                self.state = InstallState::Running;
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
                    let res = crate::patcher::apply_all(&root, false);
                    match res {
                        Ok(_) => {
                            let _ = tx_status.send(GuiEvent::Log("\n>>> Installation complete! You can now use the Friend Code Matchmaking below to play online with zero port forwarding.".to_string()));
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

            ui.add_space(6.0);

            // =================================================================
            // Online Coop (Friend Code & STUN P2P Matchmaking) Section
            // =================================================================
            let online_frame = egui::Frame::group(ui.style())
                .fill(Color32::from_rgb(20, 24, 30))
                .inner_margin(10.0);

            online_frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(
                        RichText::new("🌐 Online Coop (Friend Code & P2P Matchmaking)")
                            .size(14.0)
                            .strong(),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if let Some(ip) = self.public_ip {
                            ui.label(
                                RichText::new(format!("Public IP: {}", ip))
                                    .size(11.0)
                                    .color(Color32::from_rgb(140, 180, 220)),
                            );
                        }
                    });
                });

                ui.add_space(4.0);

                let mut action_cancel = false;
                let mut action_launch = false;

                match &mut self.match_state {
                    MatchState::Idle => {
                        ui.columns(2, |cols| {
                            // Left Column: Host a Session
                            let left_frame = egui::Frame::group(cols[0].style())
                                .fill(Color32::from_rgb(26, 32, 40))
                                .inner_margin(8.0);
                            left_frame.show(&mut cols[0], |ui| {
                                ui.label(RichText::new("Host a Session").strong().size(13.0));
                                ui.label(
                                    RichText::new(
                                        "Generates a 5-character Friend Code and waits for your friend to connect.",
                                    )
                                    .size(11.0)
                                    .color(Color32::from_rgb(180, 180, 180)),
                                );
                                ui.add_space(6.0);
                                if ui
                                    .button(
                                        RichText::new("🎮 Host New Session")
                                            .size(12.5)
                                            .strong()
                                            .color(Color32::WHITE),
                                    )
                                    .clicked()
                                {
                                    self.start_hosting(ctx);
                                }
                            });

                            // Right Column: Join a Friend
                            let right_frame = egui::Frame::group(cols[1].style())
                                .fill(Color32::from_rgb(26, 32, 40))
                                .inner_margin(8.0);
                            right_frame.show(&mut cols[1], |ui| {
                                ui.label(RichText::new("Join a Friend").strong().size(13.0));
                                ui.label(
                                    RichText::new(
                                        "Enter your friend's 5-character code to puncture NAT & connect.",
                                    )
                                    .size(11.0)
                                    .color(Color32::from_rgb(180, 180, 180)),
                                );
                                ui.add_space(4.0);
                                ui.horizontal(|ui| {
                                    let resp = ui.add(
                                        egui::TextEdit::singleline(&mut self.guest_code_input)
                                            .desired_width(75.0)
                                            .hint_text("K7X9B"),
                                    );
                                    if resp.changed() {
                                        self.guest_code_input =
                                            crate::stun::normalize_friend_code(&self.guest_code_input);
                                    }

                                    let can_join = self.guest_code_input.len() == 5;
                                    if ui
                                        .add_enabled(
                                            can_join,
                                            egui::Button::new(
                                                RichText::new("🔗 Join Session")
                                                    .size(12.0)
                                                    .strong(),
                                            ),
                                        )
                                        .clicked()
                                    {
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
                            .inner_margin(10.0);
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
                            .inner_margin(10.0);
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
                        peer_ip,
                        game_launched,
                        ..
                    } => {
                        let matched_box = egui::Frame::group(ui.style())
                            .fill(Color32::from_rgb(18, 38, 28))
                            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(80, 200, 120)))
                            .inner_margin(10.0);
                        let info_text = format!(
                            "(Code: {}, Peer IP: {}, Role: {})",
                            code,
                            peer_ip,
                            if *is_host { "Host" } else { "Guest" }
                        );
                        let is_launched = *game_launched;
                        matched_box.show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("✔ Peer Connected & Primed!")
                                        .strong()
                                        .size(14.0)
                                        .color(Color32::from_rgb(100, 240, 140)),
                                );
                                ui.label(
                                    RichText::new(info_text)
                                        .size(11.5)
                                        .color(Color32::from_rgb(180, 220, 200)),
                                );

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button(RichText::new("❌ End Match").size(11.5)).clicked() {
                                        action_cancel = true;
                                    }
                                });
                            });

                            ui.add_space(6.0);

                            if !is_launched {
                                let launch_btn = egui::Button::new(
                                    RichText::new("🚀 Launch Splinter Cell: Chaos Theory Coop")
                                        .size(14.0)
                                        .strong()
                                        .color(Color32::WHITE),
                                )
                                .fill(Color32::from_rgb(32, 140, 60))
                                .min_size(Vec2::new(ui.available_width(), 32.0));

                                if ui.add(launch_btn).clicked() {
                                    action_launch = true;
                                }
                            } else {
                                ui.label(
                                    RichText::new("✔ Game is currently running with inherited primed sockets!")
                                        .size(12.5)
                                        .strong()
                                        .color(Color32::from_rgb(120, 230, 140)),
                                );
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
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Rendezvous Server:").size(11.5));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.server_host)
                                .desired_width(180.0)
                                .hint_text("scct_coop.sholtrop.dev"),
                        );

                        ui.label(RichText::new("STUN Port:").size(11.5));
                        ui.add(egui::DragValue::new(&mut self.stun_port).range(1..=65535));

                        ui.label(RichText::new("API Port:").size(11.5));
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
}

fn run_host_match(
    server_host: String,
    stun_port: u16,
    api_port: u16,
    tx: Sender<GuiEvent>,
    cancel_rx: Receiver<()>,
    ctx: egui::Context,
) {
    let _ = tx.send(GuiEvent::Log("  [HOST] Initializing UDP sockets (9100 / 9103)...".to_string()));
    ctx.request_repaint();

    // 1. Bind UDP sockets
    let sock_disco = match std::net::UdpSocket::bind("0.0.0.0:9100") {
        Ok(s) => s,
        Err(_) => match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                let _ = tx.send(GuiEvent::MatchFailed(format!(
                    "Failed to bind Discovery socket: {:#}",
                    e
                )));
                ctx.request_repaint();
                return;
            }
        },
    };

    let sock_game = match std::net::UdpSocket::bind("0.0.0.0:9103") {
        Ok(s) => s,
        Err(_) => match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                let _ = tx.send(GuiEvent::MatchFailed(format!(
                    "Failed to bind Gameplay socket: {:#}",
                    e
                )));
                ctx.request_repaint();
                return;
            }
        },
    };

    let _ = tx.send(GuiEvent::Log(format!(
        "  [HOST] Querying STUN server ({}:{})...",
        server_host, stun_port
    )));
    ctx.request_repaint();

    // 2. Discover STUN public endpoints
    let disco_ext = match crate::stun::stun_query(&sock_disco, &server_host, stun_port) {
        Ok(addr) => addr,
        Err(e) => {
            let _ = tx.send(GuiEvent::MatchFailed(format!("STUN discovery failed: {:#}", e)));
            ctx.request_repaint();
            return;
        }
    };

    let game_ext = match crate::stun::stun_query(&sock_game, &server_host, stun_port) {
        Ok(addr) => addr,
        Err(e) => {
            let _ = tx.send(GuiEvent::MatchFailed(format!(
                "STUN discovery failed for gameplay socket: {:#}",
                e
            )));
            ctx.request_repaint();
            return;
        }
    };

    let _ = tx.send(GuiEvent::Log(format!(
        "  [HOST] Mapped public endpoints: Discovery={}, Game={}",
        disco_ext, game_ext
    )));
    ctx.request_repaint();

    // 3. Register with rendezvous server
    let code = match crate::stun::register_with_server(
        &server_host,
        api_port,
        None,
        disco_ext,
        game_ext,
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
        "  [HOST] Friend Code registered: {}",
        code
    )));
    ctx.request_repaint();

    // 4. Poll for guest connection
    loop {
        if cancel_rx.try_recv().is_ok() {
            let _ = tx.send(GuiEvent::Log("  [HOST] Hosting session cancelled.".to_string()));
            ctx.request_repaint();
            return;
        }

        thread::sleep(Duration::from_millis(1000));

        if cancel_rx.try_recv().is_ok() {
            let _ = tx.send(GuiEvent::Log("  [HOST] Hosting session cancelled.".to_string()));
            ctx.request_repaint();
            return;
        }

        match crate::stun::poll_server_for_peer(&server_host, api_port, &code) {
            Ok(Some((peer_disco, peer_game))) => {
                let _ = tx.send(GuiEvent::MatchStatus(format!(
                    "Friend connected! Punching NAT holes to {}...",
                    peer_disco.ip()
                )));
                let _ = tx.send(GuiEvent::Log(format!(
                    "  [HOST] Peer matched! Performing UDP hole punch to {} (disco={}, game={})",
                    peer_disco.ip(),
                    peer_disco.port(),
                    peer_game.port()
                )));
                ctx.request_repaint();

                // Simultaneous UDP hole punch
                crate::stun::punch_udp_holes(&sock_disco, &sock_game, peer_disco, peer_game);

                let peer_ip = match peer_disco.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => Ipv4Addr::new(127, 0, 0, 1),
                };

                let _ = tx.send(GuiEvent::Matched {
                    code,
                    is_host: true,
                    peer_ip,
                    sock_disco,
                    sock_game,
                });
                let _ = tx.send(GuiEvent::Log(
                    "  [HOST] UDP hole punch complete. Ready to launch!".to_string(),
                ));
                ctx.request_repaint();
                return;
            }
            Ok(None) => {
                // still waiting
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

fn run_join_match(
    server_host: String,
    stun_port: u16,
    api_port: u16,
    target_code: String,
    tx: Sender<GuiEvent>,
    ctx: egui::Context,
) {
    let _ = tx.send(GuiEvent::Log(format!(
        "  [JOIN] Joining friend code '{}'...",
        target_code
    )));
    ctx.request_repaint();

    // 1. Bind UDP sockets
    let sock_disco = match std::net::UdpSocket::bind("0.0.0.0:9100") {
        Ok(s) => s,
        Err(_) => match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                let _ = tx.send(GuiEvent::MatchFailed(format!(
                    "Failed to bind Discovery socket: {:#}",
                    e
                )));
                ctx.request_repaint();
                return;
            }
        },
    };

    let sock_game = match std::net::UdpSocket::bind("0.0.0.0:9103") {
        Ok(s) => s,
        Err(_) => match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                let _ = tx.send(GuiEvent::MatchFailed(format!(
                    "Failed to bind Gameplay socket: {:#}",
                    e
                )));
                ctx.request_repaint();
                return;
            }
        },
    };

    let _ = tx.send(GuiEvent::Log(format!(
        "  [JOIN] Querying STUN server ({}:{})...",
        server_host, stun_port
    )));
    ctx.request_repaint();

    // 2. Discover STUN public endpoints
    let disco_ext = match crate::stun::stun_query(&sock_disco, &server_host, stun_port) {
        Ok(addr) => addr,
        Err(e) => {
            let _ = tx.send(GuiEvent::MatchFailed(format!("STUN discovery failed: {:#}", e)));
            ctx.request_repaint();
            return;
        }
    };

    let game_ext = match crate::stun::stun_query(&sock_game, &server_host, stun_port) {
        Ok(addr) => addr,
        Err(e) => {
            let _ = tx.send(GuiEvent::MatchFailed(format!(
                "STUN discovery failed for gameplay socket: {:#}",
                e
            )));
            ctx.request_repaint();
            return;
        }
    };

    let _ = tx.send(GuiEvent::Log(format!(
        "  [JOIN] Mapped public endpoints: Discovery={}, Game={}",
        disco_ext, game_ext
    )));
    let _ = tx.send(GuiEvent::MatchStatus(
        "Exchanging rendezvous endpoints with host...".to_string(),
    ));
    ctx.request_repaint();

    // 3. Connect via rendezvous server
    let (peer_disco, peer_game) = match crate::stun::join_with_server(
        &server_host,
        api_port,
        &target_code,
        disco_ext,
        game_ext,
    ) {
        Ok(pair) => pair,
        Err(e) => {
            let _ = tx.send(GuiEvent::MatchFailed(format!(
                "Failed to connect with friend code '{}': {:#}",
                target_code, e
            )));
            ctx.request_repaint();
            return;
        }
    };

    let _ = tx.send(GuiEvent::MatchStatus(format!(
        "Host located at {}! Punching NAT holes...",
        peer_disco.ip()
    )));
    let _ = tx.send(GuiEvent::Log(format!(
        "  [JOIN] Host matched! Performing UDP hole punch to {} (disco={}, game={})",
        peer_disco.ip(),
        peer_disco.port(),
        peer_game.port()
    )));
    ctx.request_repaint();

    // 4. Simultaneous UDP hole punch
    crate::stun::punch_udp_holes(&sock_disco, &sock_game, peer_disco, peer_game);

    let peer_ip = match peer_disco.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => Ipv4Addr::new(127, 0, 0, 1),
    };

    let _ = tx.send(GuiEvent::Matched {
        code: target_code,
        is_host: false,
        peer_ip,
        sock_disco,
        sock_game,
    });
    let _ = tx.send(GuiEvent::Log(
        "  [JOIN] UDP hole punch complete. Ready to launch!".to_string(),
    ));
    ctx.request_repaint();
}

pub fn run_gui(explicit_dir: Option<PathBuf>) -> eframe::Result {
    let mut wgpu_options = eframe::egui_wgpu::WgpuConfiguration::default();
    if let eframe::egui_wgpu::WgpuSetup::CreateNew(ref mut setup) = wgpu_options.wgpu_setup {
        setup.instance_descriptor.backends = eframe::wgpu::Backends::all();
        setup.instance_descriptor.flags |=
            eframe::wgpu::InstanceFlags::ALLOW_UNDERLYING_NONCOMPLIANT_ADAPTER;
        setup.power_preference = eframe::wgpu::PowerPreference::None;
        setup.native_adapter_selector = Some(std::sync::Arc::new(|adapters, surface| {
            // 1. Try finding a hardware GPU (discrete or integrated) compatible with surface
            if let Some(surface) = surface
                && let Some(adapter) = adapters.iter().find(|a| {
                    a.get_info().device_type != eframe::wgpu::DeviceType::Cpu
                        && a.is_surface_supported(surface)
                })
            {
                return Ok(adapter.clone());
            }

            // 2. Try any adapter compatible with surface (including CPU / WARP / llvmpipe)
            if let Some(surface) = surface
                && let Some(adapter) = adapters.iter().find(|a| a.is_surface_supported(surface))
            {
                return Ok(adapter.clone());
            }

            // 3. Fallback to any hardware adapter
            if let Some(adapter) = adapters
                .iter()
                .find(|a| a.get_info().device_type != eframe::wgpu::DeviceType::Cpu)
            {
                return Ok(adapter.clone());
            }

            // 4. Fallback to any adapter at all (CPU / software rasterizer)
            if let Some(adapter) = adapters.first() {
                return Ok(adapter.clone());
            }

            Err("No graphics adapter (hardware or CPU fallback) found on this machine".to_string())
        }));
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([780.0, 680.0])
            .with_min_inner_size([540.0, 480.0])
            .with_title("SCCT Coop Mod Installer & Online Launcher"),
        wgpu_options,
        ..Default::default()
    };

    eframe::run_native(
        "SCCT Coop Mod Installer & Online Launcher",
        options,
        Box::new(move |cc| Ok(Box::new(PatcherApp::new(cc, explicit_dir)))),
    )
}
