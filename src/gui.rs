use eframe::egui::{self, Color32, RichText, ScrollArea, Vec2};
use std::path::PathBuf;
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
    resolved_root: Option<PathBuf>,
    detection_msg: String,
    state: InstallState,
    log_lines: Vec<String>,
    receiver: Receiver<String>,
    sender: Sender<String>,
}

impl PatcherApp {
    pub fn new(_cc: &eframe::CreationContext, explicit_dir: Option<PathBuf>) -> Self {
        let (resolved_root, detection_msg) =
            match crate::patcher::resolve_game_root(explicit_dir.as_deref()) {
                Ok(root) => {
                    let sys = crate::patcher::find_child_ci(&root, "System");
                    let exe = crate::patcher::find_child_ci(&sys, "splintercell3.exe");
                    if exe.is_file() {
                        (
                            Some(root.clone()),
                            format!("Game detected: {}", root.display()),
                        )
                    } else {
                        (
                            None,
                            "Could not find splintercell3.exe. Please place this .exe inside your Splinter Cell Chaos Theory/System folder."
                                .to_string(),
                        )
                    }
                }
                Err(e) => (None, format!("Path resolution error: {:#}", e)),
            };

        let (sender, receiver) = channel();

        Self {
            resolved_root,
            detection_msg,
            state: InstallState::Idle,
            log_lines: Vec::new(),
            receiver,
            sender,
        }
    }
}

impl eframe::App for PatcherApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll for log updates from background thread
        while let Ok(msg) = self.receiver.try_recv() {
            if msg == "__SCCT_DONE_OK__" {
                self.state = InstallState::Success;
            } else if msg == "__SCCT_DONE_ERR__" {
                self.state = InstallState::Failed;
            } else {
                self.log_lines.push(msg);
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);

            // Title
            ui.heading(RichText::new("Splinter Cell: Chaos Theory — Coop Mod").strong().size(22.0));
            ui.label(
                RichText::new("Convert all 11 Single Player missions to Coop + fix multi-NIC LAN/ZeroTier")
                    .size(13.0)
                    .color(Color32::from_rgb(180, 180, 180)),
            );

            ui.add_space(10.0);

            // Detection Status
            if self.resolved_root.is_some() {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("✔").color(Color32::from_rgb(80, 220, 100)).strong());
                    ui.label(RichText::new(&self.detection_msg).color(Color32::from_rgb(120, 230, 140)).size(13.0));
                });
            } else {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("⚠").color(Color32::from_rgb(255, 100, 100)).strong());
                    ui.label(RichText::new(&self.detection_msg).color(Color32::from_rgb(255, 120, 120)).size(13.0));
                });
            }

            ui.add_space(14.0);

            // Single Main Action Button
            let can_click = self.state != InstallState::Running && self.resolved_root.is_some();
            let button_text = match self.state {
                InstallState::Idle => "Install Coop Mod",
                InstallState::Running => "Installing Coop Mod... (Please wait)",
                InstallState::Success => "✔ Mod Installed Successfully (Click to Reinstall)",
                InstallState::Failed => "❌ Installation Failed (Click to Retry)",
            };

            let btn = egui::Button::new(
                RichText::new(button_text)
                    .size(16.0)
                    .strong()
                    .color(if can_click { Color32::WHITE } else { Color32::from_rgb(160, 160, 160) }),
            )
            .min_size(Vec2::new(ui.available_width(), 44.0));

            if ui.add_enabled(can_click, btn).clicked() {
                self.state = InstallState::Running;
                self.log_lines.clear();

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

            ui.add_space(14.0);

            // Output Log Console
            ui.label(RichText::new("Stdout / Log Output:").strong().size(13.0));
            ui.add_space(4.0);

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
                                RichText::new("Ready. Click 'Install Coop Mod' above to begin.")
                                    .monospace()
                                    .size(12.0)
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
                                } else if line.contains("[NET]") || line.contains("[UMD]") {
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
            .with_inner_size([740.0, 540.0])
            .with_min_inner_size([520.0, 360.0])
            .with_title("SCCT Coop Mod Installer"),
        ..Default::default()
    };

    eframe::run_native(
        "SCCT Coop Mod Installer",
        options,
        Box::new(move |cc| Ok(Box::new(PatcherApp::new(cc, explicit_dir)))),
    )
}
