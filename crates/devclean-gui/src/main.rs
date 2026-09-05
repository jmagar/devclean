use camino::Utf8PathBuf;
use devclean::config::{Config, Presentation, ScanLimits};
use devclean::report::ScanReportV1;
use devclean_gui::TierFilter;
use devclean_gui::service::AppService;
use gpui::{
    App, AppContext, Application, Bounds, Context, WindowBounds, WindowOptions, point, px, size,
};

const BG: u32 = 0x0b0f14;
const SURFACE: u32 = 0x121821;
const SURFACE_RAISED: u32 = 0x18212d;
const BORDER: u32 = 0x263241;
const TEXT: u32 = 0xe8edf2;
const MUTED: u32 = 0x8e9aa8;
const ACCENT: u32 = 0x62d5a7;
const ACCENT_DARK: u32 = 0x173f35;
const AMBER: u32 = 0xf1bd67;
const RED: u32 = 0xef7b7b;
const VIOLET: u32 = 0xb79aff;
const FINDINGS_PAGE_SIZE: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Page {
    Overview,
    Findings,
    Scope,
}

#[derive(Clone, Debug)]
enum ScanState {
    Idle,
    Scanning,
    Cancelling,
    Ready,
    Error(String),
}

struct DevcleanApp {
    service: Option<AppService>,
    config: Config,
    report: Option<ScanReportV1>,
    page: Page,
    filter: TierFilter,
    selected: Option<usize>,
    findings_page: usize,
    filtered_indices: Vec<usize>,
    scan_state: ScanState,
    toast: Option<String>,
}

impl Drop for DevcleanApp {
    fn drop(&mut self) {
        if let Some(service) = &self.service {
            service.cancel_scan();
        }
    }
}

impl DevcleanApp {
    fn new(cx: &mut Context<Self>) -> Self {
        let mut boot_error = None;
        let service = match AppService::discover() {
            Ok(service) => match service
                .ensure_initialized()
                .and_then(|()| service.load_config())
            {
                Ok(config) => Some((service, config)),
                Err(error) => {
                    boot_error = Some(format!("Devclean needs attention: {error}"));
                    None
                }
            },
            Err(error) => {
                boot_error = Some(format!("Devclean needs attention: {error}"));
                None
            }
        };
        let mut app = Self {
            service: service.as_ref().map(|(service, _)| service.clone()),
            config: service
                .map(|(_, config)| config)
                .unwrap_or_else(empty_config),
            report: None,
            page: Page::Overview,
            filter: TierFilter::All,
            selected: None,
            findings_page: 0,
            filtered_indices: Vec::new(),
            scan_state: boot_error.map(ScanState::Error).unwrap_or(ScanState::Idle),
            toast: None,
        };
        if app.service.is_some() {
            app.load_latest(cx);
        }
        cx.notify();
        app
    }

    fn load_latest(&mut self, cx: &mut Context<Self>) {
        let Some(service) = self.service.clone() else {
            return;
        };
        let task = cx
            .background_executor()
            .spawn(async move { service.load_latest() });
        cx.spawn(async move |this, cx| {
            let result = task.await;
            let _ = this.update(cx, |this, cx| {
                match result {
                    Ok(Some(report)) => {
                        this.report = Some(report);
                        this.refresh_filtered_indices();
                        this.scan_state = ScanState::Ready;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        this.scan_state = ScanState::Error(format!(
                            "The latest saved report could not be restored: {error}"
                        ));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn service_or_message(&mut self) -> Option<AppService> {
        match self.service.clone() {
            Some(service) => Some(service),
            None => {
                self.toast = Some(
                    "Devclean storage is unavailable; fix the startup error and relaunch".into(),
                );
                None
            }
        }
    }

    fn start_scan(&mut self, cx: &mut Context<Self>) {
        let Some(service) = self.service_or_message() else {
            cx.notify();
            return;
        };
        if matches!(self.scan_state, ScanState::Scanning) {
            return;
        }
        if self.config.approved_roots.is_empty() && self.config.approved_caches.is_empty() {
            self.page = Page::Scope;
            self.toast = Some("Choose at least one scan location first".into());
            cx.notify();
            return;
        }
        self.scan_state = ScanState::Scanning;
        self.toast = None;
        cx.notify();
        let task = cx
            .background_executor()
            .spawn(async move { service.scan() });
        cx.spawn(async move |this, cx| {
            let result = task.await;
            let _ = this.update(cx, |this, cx| {
                match result {
                    Ok(report) => {
                        this.report = Some(report);
                        this.refresh_filtered_indices();
                        this.scan_state = ScanState::Ready;
                        this.page = Page::Findings;
                        this.selected = None;
                        this.toast = Some("Scan complete · no files were changed".into());
                    }
                    Err(_error) if matches!(this.scan_state, ScanState::Cancelling) => {
                        this.scan_state = ScanState::Idle;
                        this.toast = Some("Scan cancelled · no files were changed".into());
                    }
                    Err(error) => this.scan_state = ScanState::Error(error),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn cancel_scan(&mut self, cx: &mut Context<Self>) {
        if let Some(service) = &self.service {
            service.cancel_scan();
            self.scan_state = ScanState::Cancelling;
            self.toast = Some("Cancelling scan…".into());
            cx.notify();
        }
    }

    fn refresh_filtered_indices(&mut self) {
        self.filtered_indices = self
            .report
            .as_ref()
            .map(|report| {
                report
                    .candidates
                    .iter()
                    .enumerate()
                    .filter_map(|(index, candidate)| {
                        self.filter.matches(candidate.tier).then_some(index)
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.findings_page = 0;
        self.selected = None;
    }

    fn choose_root(&mut self, cx: &mut Context<Self>) {
        let Some(service) = self.service_or_message() else {
            cx.notify();
            return;
        };
        let Some(path) = rfd::FileDialog::new()
            .set_title("Add scan location")
            .pick_folder()
        else {
            return;
        };
        let Ok(path) = Utf8PathBuf::from_path_buf(path) else {
            self.toast = Some("That folder name is not valid UTF-8".into());
            cx.notify();
            return;
        };
        match service.add_root(path) {
            Ok(config) => {
                self.config = config;
                self.toast = Some("Scan location added".into());
            }
            Err(error) => self.toast = Some(error),
        }
        cx.notify();
    }

    fn export_report(&mut self, cx: &mut Context<Self>) {
        let Some(service) = self.service_or_message() else {
            cx.notify();
            return;
        };
        let Some(report) = &self.report else { return };
        let suggested = format!("{}-redacted.json", report.scan_id);
        let Some(path) = rfd::FileDialog::new()
            .set_title("Export redacted report")
            .set_file_name(suggested)
            .save_file()
        else {
            return;
        };
        let Ok(path) = Utf8PathBuf::from_path_buf(path) else {
            self.toast = Some("That export path is not valid UTF-8".into());
            cx.notify();
            return;
        };
        self.toast = Some(match service.export_redacted(report, &path) {
            Ok(()) => format!("Redacted report exported to {path}"),
            Err(error) => error,
        });
        cx.notify();
    }

    fn import_config(&mut self, cx: &mut Context<Self>) {
        let Some(service) = self.service_or_message() else {
            cx.notify();
            return;
        };
        let Some(path) = rfd::FileDialog::new()
            .set_title("Import and approve devclean configuration")
            .add_filter("TOML configuration", &["toml"])
            .pick_file()
        else {
            return;
        };
        let Ok(path) = Utf8PathBuf::from_path_buf(path) else {
            self.toast = Some("That configuration path is not valid UTF-8".into());
            cx.notify();
            return;
        };
        match service.import_config(&path) {
            Ok(config) => {
                self.config = config;
                self.toast = Some("Configuration validated and imported".into());
            }
            Err(error) => self.toast = Some(format!("Configuration rejected: {error}")),
        }
        cx.notify();
    }

    fn remove_root(&mut self, path: Utf8PathBuf, cx: &mut Context<Self>) {
        let Some(service) = self.service_or_message() else {
            cx.notify();
            return;
        };
        match service.remove_root(&path) {
            Ok(config) => {
                self.config = config;
                self.toast = Some("Scan location removed".into());
            }
            Err(error) => self.toast = Some(error),
        }
        cx.notify();
    }
}

mod view;

fn main() {
    Application::new().run(|cx: &mut App| {
        let bounds = Bounds::centered(None, size(px(1240.), px(780.)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(900.), px(620.))),
                titlebar: Some(gpui::TitlebarOptions {
                    title: None,
                    appears_transparent: true,
                    traffic_light_position: Some(point(px(14.), px(12.))),
                }),
                ..Default::default()
            },
            |_, cx| cx.new(DevcleanApp::new),
        )
        .expect("open devclean window");
        cx.activate(true);
    });
}

fn empty_config() -> Config {
    Config {
        approved_roots: Default::default(),
        approved_caches: Default::default(),
        exclusions: Default::default(),
        docker: None,
        presentation: Presentation { terminal_rows: 20 },
        limits: ScanLimits::default(),
    }
}
