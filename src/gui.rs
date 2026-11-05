use eframe::egui::{self, Color32, RichText, ScrollArea, Vec2};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

#[derive(Debug, PartialEq, Eq)]
enum InstallState {
    Idle,
    Running,
    Success,
    Failed,
}

pub struct PatcherApp {
    game_dir_input: String,
    resolved_root: Option<PathBuf>,
    detected_roots: Vec<PathBuf>,
    detection_msg: String,
    state: InstallState,
    log_lines: Vec<String>,
    receiver: Receiver<String>,
    sender: Sender<String>,

    // Online & UPnP state
    host_ip_input: String,
    configured_host_ip: Option<Ipv4Addr>,
    public_ip: Option<Ipv4Addr>,
    upnp_status_msg: Option<String>,
    upnp_active: bool,
    upnp_running: bool,
    online_patch_applied: bool,
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
            host_ip_input: String::new(),
            configured_host_ip: None,
            public_ip: None,
            upnp_status_msg: None,
            upnp_active: false,
            upnp_running: false,
            online_patch_applied: false,
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
            // Exactly one detected: auto-fill and select
            app.set_game_root(detected[0].clone());
        } else if detected.len() > 1 {
            // Multiple detected: select first and notify user
            app.set_game_root(detected[0].clone());
            app.detection_msg = format!(
                "Auto-detected {} game installations. Selected: {}",
                detected.len(),
                detected[0].display()
            );
        } else {
            // None detected
            app.detection_msg =
                "Splinter Cell Chaos Theory not detected. Please browse to your game folder."
                    .to_string();
        }

        app
    }

    pub fn set_game_root(&mut self, root: PathBuf) {
        self.game_dir_input = root.display().to_string();
        self.detection_msg = format!("Game detected: {}", root.display());
        self.resolved_root = Some(root.clone());

        // Reload online settings from the new root
        let sys = crate::patcher::find_child_ci(&root, "System");
        let ini_path = sys.join("direct_ip.ini");
        if let Some(ip) = crate::net::load_direct_ip_ini(&ini_path) {
            self.host_ip_input = ip.to_string();
            self.configured_host_ip = Some(ip);
        } else {
            self.configured_host_ip = None;
        }

        let exe_path = crate::patcher::find_child_ci(&sys, "splintercell3.exe");
        if let Ok(pe_bytes) = std::fs::read(&exe_path) {
            self.online_patch_applied = crate::net::is_online_coop_fix_applied(&pe_bytes);
            if self.configured_host_ip.is_none()
                && let Some(ip) = crate::net::get_direct_ip_from_exe(&pe_bytes)
            {
                self.host_ip_input = ip.to_string();
                self.configured_host_ip = Some(ip);
            }
        } else {
            self.online_patch_applied = false;
        }
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
}

impl eframe::App for PatcherApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll for log updates and background tasks
        while let Ok(msg) = self.receiver.try_recv() {
            if msg == "__SCCT_DONE_OK__" {
                self.state = InstallState::Success;
                self.online_patch_applied = true;
            } else if msg == "__SCCT_DONE_ERR__" {
                self.state = InstallState::Failed;
            } else if let Some(rest) = msg.strip_prefix("__UPNP_RES__:") {
                self.upnp_running = false;
                // Format: <public_ip>|<ports_forwarded>|<message>
                let parts: Vec<&str> = rest.splitn(3, '|').collect();
                if parts.len() == 3 {
                    if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                        self.public_ip = Some(ip);
                    }
                    self.upnp_active = parts[1] == "true";
                    self.upnp_status_msg = Some(parts[2].to_string());
                }
            } else {
                self.log_lines.push(msg);
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
                    "Convert all 11 Single Player missions to Coop + Direct IP Online & Multi-NIC LAN",
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

                // Save configured host IP to INI before running install
                if let Some(ref root) = self.resolved_root {
                    let sys = crate::patcher::find_child_ci(root, "System");
                    let ini_path = sys.join("direct_ip.ini");
                    let trimmed = self.host_ip_input.trim();
                    let target_ip = if !trimmed.is_empty() {
                        trimmed.parse::<Ipv4Addr>().ok()
                    } else {
                        None
                    };
                    let _ = crate::net::save_direct_ip_ini(&ini_path, target_ip);
                }

                let tx = self.sender.clone();
                let tx_status = self.sender.clone();
                let ctx_clone = ctx.clone();
                let root = self.resolved_root.clone().unwrap();

                crate::patcher::set_log_sink(move |msg| {
                    let _ = tx.send(msg.to_string());
                    ctx_clone.request_repaint();
                });

                let ctx_finish = ctx.clone();
                thread::spawn(move || {
                    let res = crate::patcher::apply_all(&root, false);
                    match res {
                        Ok(_) => {
                            let _ = tx_status.send("\n>>> Installation complete! You can now launch Chaos Theory and host or join Coop.".to_string());
                            let _ = tx_status.send("__SCCT_DONE_OK__".to_string());
                        }
                        Err(e) => {
                            let _ = tx_status.send(format!("\n>>> ERROR: {:#}", e));
                            let _ = tx_status.send("__SCCT_DONE_ERR__".to_string());
                        }
                    }
                    crate::patcher::clear_log_sink();
                    ctx_finish.request_repaint();
                });
            }

            ui.add_space(6.0);

            // =================================================================
            // Online Coop (Public IP & UPnP) Section
            // =================================================================
            let online_frame = egui::Frame::group(ui.style())
                .fill(Color32::from_rgb(22, 26, 32))
                .inner_margin(10.0);

            online_frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(RichText::new("🌐 Online Coop (Direct IP & UPnP)").size(14.0).strong());
                    if self.online_patch_applied {
                        ui.label(RichText::new("✔ Online Patch Active").color(Color32::from_rgb(100, 220, 140)).size(11.5));
                    }
                });

                ui.add_space(3.0);

                // --- Hosting Section (UPnP) ---
                ui.horizontal(|ui| {
                    let upnp_btn_text = if self.upnp_running {
                        "Searching for UPnP Router..."
                    } else if self.upnp_active {
                        "✔ Ports Forwarded (Re-run UPnP)"
                    } else {
                        "Open Ports via UPnP & Get My IP"
                    };

                    let upnp_can_click = !self.upnp_running && self.state != InstallState::Running;
                    let btn = egui::Button::new(
                        RichText::new(upnp_btn_text).size(12.0).strong()
                    );

                    if ui.add_enabled(upnp_can_click, btn).clicked() {
                        self.upnp_running = true;
                        let tx = self.sender.clone();
                        let ctx_clone = ctx.clone();
                        thread::spawn(move || {
                            let res = crate::upnp::open_coop_ports();
                            match res {
                                Ok(status) => {
                                    let ip_str = status.public_ip.map(|ip| ip.to_string()).unwrap_or_default();
                                    let _ = tx.send(format!("  [UPNP] {}", status.message));
                                    let _ = tx.send(format!("__UPNP_RES__:{}:{}|{}", ip_str, status.ports_forwarded, status.message));
                                }
                                Err(e) => {
                                    let _ = tx.send(format!("  [UPNP] Error: {:#}", e));
                                    let _ = tx.send(format!("__UPNP_RES__:||false|Error: {:#}", e));
                                }
                            }
                            ctx_clone.request_repaint();
                        });
                    }

                    if let Some(ip) = self.public_ip {
                        ui.label(RichText::new("Your Public IP:").strong().size(12.0));
                        ui.label(
                            RichText::new(ip.to_string())
                                .color(Color32::from_rgb(120, 210, 255))
                                .strong()
                                .monospace()
                                .size(12.5),
                        );
                        if ui.button(RichText::new("📋 Copy").size(11.0)).clicked() {
                            ctx.copy_text(ip.to_string());
                            self.log_lines.push(format!("  [GUI] Copied public IP {} to clipboard", ip));
                        }
                    }
                });

                if let Some(ref msg) = self.upnp_status_msg {
                    let color = if self.upnp_active {
                        Color32::from_rgb(130, 220, 150)
                    } else {
                        Color32::from_rgb(255, 180, 100)
                    };
                    ui.label(RichText::new(msg).size(11.0).color(color));
                }

                ui.add_space(3.0);
                ui.separator();
                ui.add_space(3.0);

                // --- Joining Section (Host IP Input) ---
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Friend's Host IP:").strong().size(12.0));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.host_ip_input)
                            .desired_width(140.0)
                            .hint_text("e.g. 82.165.45.112"),
                    );

                    let trimmed = self.host_ip_input.trim();
                    let parsed_ip = trimmed.parse::<Ipv4Addr>().ok();

                    let can_set = self.resolved_root.is_some() && parsed_ip.is_some();
                    if ui.add_enabled(can_set, egui::Button::new("Set Host IP")).clicked()
                        && let Some(ip) = parsed_ip
                        && let Some(ref root) = self.resolved_root
                    {
                        match crate::patcher::apply_online_patch(root, Some(ip)) {
                            Ok(_) => {
                                self.configured_host_ip = Some(ip);
                                self.online_patch_applied = true;
                                self.log_lines.push(format!("  [NET] Direct Host IP set to {} (saved to direct_ip.ini)", ip));
                                self.log_lines.push("  [NET] In-game 'Online' button will now join this host!".to_string());
                            }
                            Err(e) => {
                                self.log_lines.push(format!("  [NET] Failed to apply host IP: {:#}", e));
                            }
                        }
                    }

                    if ui.button("Clear (Local LAN)").clicked() {
                        self.host_ip_input.clear();
                        if let Some(ref root) = self.resolved_root {
                            let _ = crate::patcher::apply_online_patch(root, None);
                            self.configured_host_ip = None;
                            self.log_lines.push("  [NET] Host IP cleared. Online mode reverted to local LAN broadcast.".to_string());
                        }
                    }
                });

                if let Some(target) = self.configured_host_ip {
                    ui.label(
                        RichText::new(format!("Active Target: Joining Host at {}", target))
                            .color(Color32::from_rgb(120, 220, 255))
                            .size(11.0),
                    );
                } else {
                    ui.label(
                        RichText::new("Active Target: Local LAN broadcast (No remote IP set)")
                            .color(Color32::from_rgb(180, 180, 180))
                            .size(11.0),
                    );
                }
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
                                } else if line.contains("Success!") || line.starts_with(">>> Installation complete") {
                                    Color32::from_rgb(100, 255, 130)
                                } else if line.contains("ERROR") || line.contains("Failed") {
                                    Color32::from_rgb(255, 100, 100)
                                } else if line.contains("[COOP]") {
                                    Color32::from_rgb(230, 230, 130)
                                } else if line.contains("[UPNP]") || line.contains("[NET]") || line.contains("[UMD]") || line.contains("[MD5]") {
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

pub fn run_gui(explicit_dir: Option<PathBuf>) -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([780.0, 620.0])
            .with_min_inner_size([540.0, 400.0])
            .with_title("SCCT Coop Mod Installer & Online Launcher"),
        ..Default::default()
    };

    eframe::run_native(
        "SCCT Coop Mod Installer & Online Launcher",
        options,
        Box::new(move |cc| Ok(Box::new(PatcherApp::new(cc, explicit_dir)))),
    )
}
