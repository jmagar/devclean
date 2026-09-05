use camino::Utf8PathBuf;
use devclean::config::Config;
use devclean::report::ScanReportV1;
use devclean_core::{AdvisoryCandidate, CoverageStatus, Tier};
use devclean_gui::service::AppService;
use devclean_gui::{
    TierFilter, candidate_location, category_label, filter_candidates, format_bytes,
};
use gpui::{
    AnyElement, App, Application, Bounds, Context, FontWeight, MouseButton, Render, SharedString,
    Window, WindowBounds, WindowOptions, div, point, prelude::*, px, rgb, size,
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
    Ready,
    Error(String),
}

struct DevcleanApp {
    service: AppService,
    config: Config,
    report: Option<ScanReportV1>,
    page: Page,
    filter: TierFilter,
    selected: Option<usize>,
    scan_state: ScanState,
    toast: Option<String>,
}

impl DevcleanApp {
    fn new(cx: &mut Context<Self>) -> Self {
        let service = AppService::discover().expect("devclean app paths");
        service
            .ensure_initialized()
            .expect("initialize devclean store");
        let config = service.load_config().expect("load devclean config");
        let report = service.load_latest().ok().flatten();
        let scan_state = if report.is_some() {
            ScanState::Ready
        } else {
            ScanState::Idle
        };
        let app = Self {
            service,
            config,
            report,
            page: Page::Overview,
            filter: TierFilter::All,
            selected: None,
            scan_state,
            toast: None,
        };
        cx.notify();
        app
    }

    fn start_scan(&mut self, cx: &mut Context<Self>) {
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
        let service = self.service.clone();
        let task = cx
            .background_executor()
            .spawn(async move { service.scan() });
        cx.spawn(async move |this, cx| {
            let result = task.await;
            let _ = this.update(cx, |this, cx| {
                match result {
                    Ok(report) => {
                        this.report = Some(report);
                        this.scan_state = ScanState::Ready;
                        this.page = Page::Findings;
                        this.selected = None;
                        this.toast = Some("Scan complete · no files were changed".into());
                    }
                    Err(error) => this.scan_state = ScanState::Error(error),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn choose_root(&mut self, cx: &mut Context<Self>) {
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
        match self.service.add_root(path) {
            Ok(config) => {
                self.config = config;
                self.toast = Some("Scan location added".into());
            }
            Err(error) => self.toast = Some(error),
        }
        cx.notify();
    }

    fn export_report(&mut self, cx: &mut Context<Self>) {
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
        self.toast = Some(match self.service.export_redacted(report, &path) {
            Ok(()) => format!("Redacted report exported to {path}"),
            Err(error) => error,
        });
        cx.notify();
    }

    fn import_config(&mut self, cx: &mut Context<Self>) {
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
        match self.service.import_config(&path) {
            Ok(config) => {
                self.config = config;
                self.toast = Some("Configuration validated and imported".into());
            }
            Err(error) => self.toast = Some(format!("Configuration rejected: {error}")),
        }
        cx.notify();
    }

    fn remove_root(&mut self, path: Utf8PathBuf, cx: &mut Context<Self>) {
        match self.service.remove_root(&path) {
            Ok(config) => {
                self.config = config;
                self.toast = Some("Scan location removed".into());
            }
            Err(error) => self.toast = Some(error),
        }
        cx.notify();
    }

    fn counts(&self) -> [usize; 4] {
        let mut counts = [0; 4];
        if let Some(report) = &self.report {
            for candidate in &report.candidates {
                counts[match candidate.tier {
                    Tier::Safe => 0,
                    Tier::Review => 1,
                    Tier::Protected => 2,
                    Tier::Unknown => 3,
                }] += 1;
            }
        }
        counts
    }

    fn total_size(&self) -> u64 {
        self.report
            .as_ref()
            .map(|r| {
                r.candidates
                    .iter()
                    .filter(|c| c.tier == Tier::Safe)
                    .filter_map(|c| c.physical_bytes_estimate.or(c.logical_bytes_estimate))
                    .sum()
            })
            .unwrap_or(0)
    }

    fn nav_item(&self, page: Page, label: &str, glyph: &str, cx: &Context<Self>) -> AnyElement {
        let active = self.page == page;
        div()
            .id(SharedString::from(format!("nav-{label}")))
            .h(px(42.))
            .px_3()
            .flex()
            .items_center()
            .gap_3()
            .rounded_lg()
            .cursor_pointer()
            .text_sm()
            .font_weight(if active {
                FontWeight::SEMIBOLD
            } else {
                FontWeight::NORMAL
            })
            .text_color(rgb(if active { TEXT } else { MUTED }))
            .bg(rgb(if active { SURFACE_RAISED } else { SURFACE }))
            .hover(|style| style.bg(rgb(SURFACE_RAISED)).text_color(rgb(TEXT)))
            .child(
                div()
                    .w(px(20.))
                    .text_color(rgb(if active { ACCENT } else { MUTED }))
                    .child(glyph.to_string()),
            )
            .child(label.to_string())
            .on_click(cx.listener(move |this, _, _, cx| {
                this.page = page;
                cx.notify();
            }))
            .into_any_element()
    }

    fn button(
        &self,
        id: &'static str,
        label: impl Into<SharedString>,
        primary: bool,
        cx: &Context<Self>,
        action: impl Fn(&mut Self, &mut Context<Self>) + 'static,
    ) -> AnyElement {
        let label = label.into();
        div()
            .id(id)
            .h(px(38.))
            .px_4()
            .flex()
            .items_center()
            .justify_center()
            .rounded_lg()
            .cursor_pointer()
            .text_sm()
            .font_weight(FontWeight::SEMIBOLD)
            .bg(rgb(if primary { ACCENT } else { SURFACE_RAISED }))
            .text_color(rgb(if primary { BG } else { TEXT }))
            .border_1()
            .border_color(rgb(if primary { ACCENT } else { BORDER }))
            .hover(move |style| style.opacity(0.88))
            .active(|style| style.opacity(0.72))
            .child(label)
            .on_click(cx.listener(move |this, _, _, cx| action(this, cx)))
            .into_any_element()
    }

    fn sidebar(&self, cx: &Context<Self>) -> AnyElement {
        div()
            .w(px(228.))
            .h_full()
            .flex_none()
            .p_4()
            .flex()
            .flex_col()
            .justify_between()
            .bg(rgb(SURFACE))
            .border_r_1()
            .border_color(rgb(BORDER))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_5()
                    .child(
                        div()
                            .h(px(48.))
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(
                                div()
                                    .size(px(34.))
                                    .rounded_lg()
                                    .bg(rgb(ACCENT))
                                    .text_color(rgb(BG))
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .font_weight(FontWeight::BOLD)
                                    .child("d"),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .child(
                                        div()
                                            .font_weight(FontWeight::BOLD)
                                            .text_color(rgb(TEXT))
                                            .child("devclean"),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(rgb(MUTED))
                                            .child("Developer hygiene"),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(self.nav_item(Page::Overview, "Overview", "⌂", cx))
                            .child(self.nav_item(Page::Findings, "Findings", "◫", cx))
                            .child(self.nav_item(Page::Scope, "Scan locations", "◎", cx)),
                    ),
            )
            .child(
                div()
                    .p_3()
                    .rounded_lg()
                    .bg(rgb(ACCENT_DARK))
                    .border_1()
                    .border_color(rgb(0x285c4c))
                    .child(
                        div()
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(ACCENT))
                            .child("READ-ONLY BY DESIGN"),
                    )
                    .child(
                        div()
                            .mt_2()
                            .text_xs()
                            .line_height(px(18.))
                            .text_color(rgb(0x9fb8af))
                            .child(
                                "Devclean inventories and explains. It never deletes your files.",
                            ),
                    ),
            )
            .into_any_element()
    }

    fn custom_chrome(&self) -> AnyElement {
        div()
            .h(px(38.))
            .w_full()
            .flex_none()
            .flex()
            .items_center()
            .justify_center()
            .bg(rgb(0x0e141c))
            .border_b_1()
            .border_color(rgb(BORDER))
            .text_xs()
            .font_weight(FontWeight::SEMIBOLD)
            .text_color(rgb(0x6f7c8b))
            .child("DEVCLEAN  ·  WORKSPACE HYGIENE")
            .on_mouse_down(MouseButton::Left, |_, window, _| {
                window.start_window_move();
            })
            .into_any_element()
    }

    fn header(&self, title: &str, subtitle: &str, cx: &Context<Self>) -> AnyElement {
        let scanning = matches!(self.scan_state, ScanState::Scanning);
        div()
            .h(px(82.))
            .flex_none()
            .px_7()
            .flex()
            .items_center()
            .justify_between()
            .border_b_1()
            .border_color(rgb(BORDER))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_xl()
                            .font_weight(FontWeight::BOLD)
                            .text_color(rgb(TEXT))
                            .child(title.to_string()),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(MUTED))
                            .child(subtitle.to_string()),
                    ),
            )
            .child(
                div()
                    .flex()
                    .gap_2()
                    .when(self.report.is_some(), |row| {
                        row.child(self.button(
                            "export-button",
                            "Export redacted",
                            false,
                            cx,
                            |this, cx| this.export_report(cx),
                        ))
                    })
                    .child(self.button(
                        "scan-button",
                        if scanning {
                            "Scanning…"
                        } else {
                            "Run new scan"
                        },
                        true,
                        cx,
                        |this, cx| this.start_scan(cx),
                    )),
            )
            .into_any_element()
    }

    fn stat_card(&self, label: &str, value: String, note: &str, color: u32) -> AnyElement {
        div()
            .flex_1()
            .min_w(px(150.))
            .p_5()
            .rounded_xl()
            .bg(rgb(SURFACE))
            .border_1()
            .border_color(rgb(BORDER))
            .child(
                div()
                    .text_xs()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(MUTED))
                    .child(label.to_string()),
            )
            .child(
                div()
                    .mt_3()
                    .text_3xl()
                    .font_weight(FontWeight::BOLD)
                    .text_color(rgb(color))
                    .child(value),
            )
            .child(
                div()
                    .mt_2()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child(note.to_string()),
            )
            .into_any_element()
    }

    fn overview(&self, cx: &Context<Self>) -> AnyElement {
        let counts = self.counts();
        let has_report = self.report.is_some();
        div()
            .size_full()
            .flex()
            .flex_col()
            .child(self.header(
                "Workspace overview",
                "A calm, evidence-first view of developer disk usage.",
                cx,
            ))
            .child(
                div()
                    .id("overview-scroll")
                    .flex_1()
                    .overflow_y_scroll()
                    .p_7()
                    .flex()
                    .flex_col()
                    .gap_6()
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_4()
                            .child(self.stat_card(
                                "SAFE TO REBUILD",
                                counts[0].to_string(),
                                "High-confidence generated artifacts",
                                ACCENT,
                            ))
                            .child(self.stat_card(
                                "NEEDS REVIEW",
                                counts[1].to_string(),
                                "Context matters before any action",
                                AMBER,
                            ))
                            .child(self.stat_card(
                                "PROTECTED",
                                counts[2].to_string(),
                                "Dirty, active, stateful, or unique",
                                RED,
                            ))
                            .child(self.stat_card(
                                "SAFE ESTIMATE",
                                format_bytes(Some(self.total_size())),
                                "Estimated allocated space only",
                                VIOLET,
                            )),
                    )
                    .child(self.hero(has_report, cx))
                    .when_some(self.report.as_ref(), |view, report| {
                        view.child(self.breakdown(report))
                    }),
            )
            .into_any_element()
    }

    fn hero(&self, has_report: bool, cx: &Context<Self>) -> AnyElement {
        let (title, body) = match &self.scan_state {
            ScanState::Scanning => (
                "Looking carefully…",
                "Devclean is measuring approved locations and checking activity, ownership, and rebuildability.",
            ),
            ScanState::Error(_) => (
                "The scan stopped safely",
                "Nothing was changed. Review the message below, then try again.",
            ),
            _ if has_report => (
                "Your workspace has been mapped",
                "Every finding includes classification evidence and protection signals. Estimates are advisory.",
            ),
            _ => (
                "Ready for your first scan",
                "Start with your configured locations. Devclean will only read and inventory them.",
            ),
        };
        div()
            .p_6()
            .rounded_xl()
            .bg(rgb(SURFACE_RAISED))
            .border_1()
            .border_color(rgb(BORDER))
            .flex()
            .justify_between()
            .items_center()
            .gap_6()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .text_lg()
                            .font_weight(FontWeight::BOLD)
                            .text_color(rgb(TEXT))
                            .child(title),
                    )
                    .child(
                        div()
                            .max_w(px(650.))
                            .text_sm()
                            .line_height(px(21.))
                            .text_color(rgb(MUTED))
                            .child(body),
                    )
                    .when_some(
                        match &self.scan_state {
                            ScanState::Error(e) => Some(e.clone()),
                            _ => None,
                        },
                        |v, e| v.child(div().mt_2().text_sm().text_color(rgb(RED)).child(e)),
                    ),
            )
            .child(self.button(
                "hero-findings",
                if has_report {
                    "Explore findings"
                } else {
                    "Choose locations"
                },
                false,
                cx,
                move |this, cx| {
                    this.page = if has_report {
                        Page::Findings
                    } else {
                        Page::Scope
                    };
                    cx.notify();
                },
            ))
            .into_any_element()
    }

    fn breakdown(&self, report: &ScanReportV1) -> AnyElement {
        let complete = report.coverage == CoverageStatus::Complete;
        div()
            .p_5()
            .rounded_xl()
            .bg(rgb(SURFACE))
            .border_1()
            .border_color(rgb(BORDER))
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .child(
                        div()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(TEXT))
                            .child("Latest scan"),
                    )
                    .child(
                        div()
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(if complete { ACCENT } else { AMBER }))
                            .child(if complete {
                                "COMPLETE COVERAGE"
                            } else {
                                "PARTIAL COVERAGE"
                            }),
                    ),
            )
            .child(
                div()
                    .mt_4()
                    .flex()
                    .gap_6()
                    .text_sm()
                    .text_color(rgb(MUTED))
                    .child(format!("{} candidates", report.candidates.len()))
                    .child(format!("{} warnings", report.warnings.len()))
                    .child(report.scan_id.clone()),
            )
            .into_any_element()
    }

    fn findings(&self, cx: &Context<Self>) -> AnyElement {
        let candidates = self
            .report
            .as_ref()
            .map(|r| filter_candidates(&r.candidates, self.filter))
            .unwrap_or_default();
        let list = candidates.into_iter().take(500).enumerate().fold(
            div().flex().flex_col().gap_2(),
            |list, (visible_index, candidate)| {
                let actual_index = self
                    .report
                    .as_ref()
                    .and_then(|r| r.candidates.iter().position(|c| c.id == candidate.id))
                    .unwrap_or(visible_index);
                list.child(self.candidate_row(candidate, actual_index, cx))
            },
        );
        div()
            .size_full()
            .flex()
            .flex_col()
            .child(self.header(
                "Findings",
                "Filter by confidence tier, then inspect the evidence behind each result.",
                cx,
            ))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .p_6()
                            .flex()
                            .flex_col()
                            .gap_4()
                            .child(self.filters(cx))
                            .child(
                                div()
                                    .id("findings-scroll")
                                    .flex_1()
                                    .min_h_0()
                                    .overflow_y_scroll()
                                    .pr_2()
                                    .child(list),
                            ),
                    )
                    .child(self.detail_panel()),
            )
            .into_any_element()
    }

    fn filters(&self, cx: &Context<Self>) -> AnyElement {
        let filters = [
            (TierFilter::All, "All"),
            (TierFilter::Safe, "Safe"),
            (TierFilter::Review, "Review"),
            (TierFilter::Protected, "Protected"),
            (TierFilter::Unknown, "Unknown"),
        ];
        filters
            .into_iter()
            .fold(div().flex().gap_2(), |row, (filter, label)| {
                let active = self.filter == filter;
                row.child(
                    div()
                        .id(SharedString::from(format!("filter-{label}")))
                        .px_3()
                        .py_2()
                        .rounded_lg()
                        .cursor_pointer()
                        .text_xs()
                        .font_weight(FontWeight::SEMIBOLD)
                        .bg(rgb(if active { ACCENT_DARK } else { SURFACE }))
                        .text_color(rgb(if active { ACCENT } else { MUTED }))
                        .border_1()
                        .border_color(rgb(if active { 0x285c4c } else { BORDER }))
                        .child(label)
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.filter = filter;
                            this.selected = None;
                            cx.notify();
                        })),
                )
            })
            .into_any_element()
    }

    fn candidate_row(
        &self,
        candidate: &AdvisoryCandidate,
        index: usize,
        cx: &Context<Self>,
    ) -> AnyElement {
        let selected = self.selected == Some(index);
        let (tier, color) = tier_style(candidate.tier);
        div()
            .id(SharedString::from(format!("candidate-{}", candidate.id.0)))
            .p_4()
            .rounded_xl()
            .cursor_pointer()
            .bg(rgb(if selected { SURFACE_RAISED } else { SURFACE }))
            .border_1()
            .border_color(rgb(if selected { color } else { BORDER }))
            .hover(|style| style.bg(rgb(SURFACE_RAISED)))
            .child(
                div()
                    .flex()
                    .justify_between()
                    .gap_4()
                    .child(
                        div()
                            .min_w_0()
                            .flex_1()
                            .child(
                                div()
                                    .text_sm()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(TEXT))
                                    .child(candidate_location(candidate)),
                            )
                            .child(
                                div()
                                    .mt_2()
                                    .flex()
                                    .gap_3()
                                    .text_xs()
                                    .text_color(rgb(MUTED))
                                    .child(category_label(&candidate.category))
                                    .child(format_bytes(
                                        candidate
                                            .physical_bytes_estimate
                                            .or(candidate.logical_bytes_estimate),
                                    )),
                            ),
                    )
                    .child(
                        div()
                            .flex_none()
                            .px_2()
                            .py_1()
                            .rounded_md()
                            .bg(rgb(darken(color)))
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(color))
                            .child(tier),
                    ),
            )
            .on_click(cx.listener(move |this, _, _, cx| {
                this.selected = Some(index);
                cx.notify();
            }))
            .into_any_element()
    }

    fn detail_panel(&self) -> AnyElement {
        let candidate = self
            .selected
            .and_then(|i| self.report.as_ref()?.candidates.get(i));
        let content = if let Some(candidate) = candidate {
            let (tier, color) = tier_style(candidate.tier);
            let evidence =
                candidate
                    .positive_evidence
                    .iter()
                    .fold(div().flex().flex_col().gap_2(), |v, e| {
                        v.child(
                            div()
                                .p_3()
                                .rounded_lg()
                                .bg(rgb(BG))
                                .child(
                                    div()
                                        .text_xs()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(TEXT))
                                        .child(format!("{:?}", e.code)),
                                )
                                .child(
                                    div()
                                        .mt_1()
                                        .text_xs()
                                        .text_color(rgb(MUTED))
                                        .child(e.source.clone()),
                                ),
                        )
                    });
            let protections = if candidate.protections.is_empty() {
                div()
                    .text_sm()
                    .text_color(rgb(MUTED))
                    .child("No protection signals were observed.")
            } else {
                candidate
                    .protections
                    .iter()
                    .fold(div().flex().flex_wrap().gap_2(), |v, p| {
                        v.child(
                            div()
                                .px_2()
                                .py_1()
                                .rounded_md()
                                .bg(rgb(0x351f25))
                                .text_xs()
                                .text_color(rgb(RED))
                                .child(p.clone()),
                        )
                    })
            };
            div()
                .flex()
                .flex_col()
                .gap_5()
                .child(
                    div()
                        .child(
                            div()
                                .text_xs()
                                .font_weight(FontWeight::BOLD)
                                .text_color(rgb(color))
                                .child(tier),
                        )
                        .child(
                            div()
                                .mt_2()
                                .text_lg()
                                .font_weight(FontWeight::BOLD)
                                .text_color(rgb(TEXT))
                                .child(category_label(&candidate.category)),
                        )
                        .child(
                            div()
                                .mt_2()
                                .text_sm()
                                .line_height(px(20.))
                                .text_color(rgb(MUTED))
                                .child(candidate_location(candidate)),
                        ),
                )
                .child(section(
                    "SIZE EVIDENCE",
                    format_bytes(
                        candidate
                            .physical_bytes_estimate
                            .or(candidate.logical_bytes_estimate),
                    ),
                ))
                .child(div().child(section_title("PROTECTIONS")).child(protections))
                .child(
                    div()
                        .child(section_title("POSITIVE EVIDENCE"))
                        .child(evidence),
                )
        } else {
            div()
                .h_full()
                .flex()
                .flex_col()
                .items_center()
                .justify_center()
                .text_center()
                .child(div().text_2xl().text_color(rgb(ACCENT)).child("◎"))
                .child(
                    div()
                        .mt_3()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(TEXT))
                        .child("Select a finding"),
                )
                .child(
                    div()
                        .mt_2()
                        .max_w(px(240.))
                        .text_sm()
                        .line_height(px(20.))
                        .text_color(rgb(MUTED))
                        .child(
                            "Its classification evidence and protection signals will appear here.",
                        ),
                )
        };
        div()
            .id("detail-scroll")
            .w(px(340.))
            .h_full()
            .flex_none()
            .p_6()
            .overflow_y_scroll()
            .bg(rgb(SURFACE))
            .border_l_1()
            .border_color(rgb(BORDER))
            .child(content)
            .into_any_element()
    }

    fn scope(&self, cx: &Context<Self>) -> AnyElement {
        let roots = self.config.approved_roots.iter().cloned().fold(
            div().flex().flex_col().gap_3(),
            |list, path| {
                let click_path = path.clone();
                list.child(
                    div()
                        .p_4()
                        .rounded_xl()
                        .bg(rgb(SURFACE))
                        .border_1()
                        .border_color(rgb(BORDER))
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap_4()
                        .child(
                            div()
                                .min_w_0()
                                .flex_1()
                                .child(
                                    div()
                                        .text_sm()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(TEXT))
                                        .child(path.to_string()),
                                )
                                .child(
                                    div()
                                        .mt_1()
                                        .text_xs()
                                        .text_color(rgb(MUTED))
                                        .child("Approved recursive scan location"),
                                ),
                        )
                        .child(
                            div()
                                .id(SharedString::from(format!("remove-{path}")))
                                .px_3()
                                .py_2()
                                .rounded_lg()
                                .cursor_pointer()
                                .text_xs()
                                .text_color(rgb(MUTED))
                                .hover(|s| s.bg(rgb(0x351f25)).text_color(rgb(RED)))
                                .child("Remove")
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.remove_root(click_path.clone(), cx)
                                })),
                        ),
                )
            },
        );
        div()
            .size_full()
            .flex()
            .flex_col()
            .child(self.header(
                "Scan locations",
                "Only explicitly approved folders are traversed.",
                cx,
            ))
            .child(
                div().id("scope-scroll").flex_1().overflow_y_scroll().p_7().child(
                    div()
                        .max_w(px(820.))
                        .child(
                            div()
                                .flex()
                                .justify_between()
                                .items_end()
                                .child(
                                    div()
                                        .child(
                                            div()
                                                .text_lg()
                                                .font_weight(FontWeight::BOLD)
                                                .text_color(rgb(TEXT))
                                                .child("Approved roots"),
                                        )
                                        .child(
                                            div()
                                                .mt_2()
                                                .text_sm()
                                                .text_color(rgb(MUTED))
                                                .child("Canonical paths only. Symlink aliases and insecure locations are rejected."),
                                        ),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .gap_2()
                                        .child(self.button(
                                            "import-config",
                                            "Import config",
                                            false,
                                            cx,
                                            |this, cx| this.import_config(cx),
                                        ))
                                        .child(self.button(
                                            "add-root",
                                            "+ Add folder",
                                            false,
                                            cx,
                                            |this, cx| this.choose_root(cx),
                                        )),
                                ),
                        )
                        .child(div().mt_5().child(roots))
                        .child(
                            div()
                                .mt_5()
                                .flex()
                                .gap_3()
                                .child(self.stat_card(
                                    "CACHE ROOTS",
                                    self.config.approved_caches.len().to_string(),
                                    "Explicitly marked re-downloadable locations",
                                    VIOLET,
                                ))
                                .child(self.stat_card(
                                    "EXCLUSIONS",
                                    self.config.exclusions.len().to_string(),
                                    "Subtrees skipped before metadata access",
                                    AMBER,
                                ))
                                .child(self.stat_card(
                                    "DOCKER",
                                    if self.config.docker.is_some() { "Pinned" } else { "Off" }
                                        .to_string(),
                                    "Requires a credential-free daemon identity",
                                    ACCENT,
                                )),
                        )
                        .child(
                            div()
                                .mt_6()
                                .p_5()
                                .rounded_xl()
                                .bg(rgb(ACCENT_DARK))
                                .border_1()
                                .border_color(rgb(0x285c4c))
                                .child(
                                    div()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(ACCENT))
                                        .child("Your safety boundary"),
                                )
                                .child(
                                    div()
                                        .mt_2()
                                        .text_sm()
                                        .line_height(px(21.))
                                        .text_color(rgb(0xaac3b9))
                                        .child("A location grants read-only inventory access. Reports cannot authorize deletion, and unknown or stateful resources remain protected."),
                                ),
                        ),
                ),
            )
            .into_any_element()
    }
}

impl Render for DevcleanApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .size_full()
            .min_w(px(900.))
            .min_h(px(620.))
            .flex()
            .flex_col()
            .bg(rgb(BG))
            .text_color(rgb(TEXT))
            .font_family("Inter")
            .child(self.custom_chrome())
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .child(self.sidebar(cx))
                    .child(div().flex_1().min_w_0().h_full().child(match self.page {
                        Page::Overview => self.overview(cx),
                        Page::Findings => self.findings(cx),
                        Page::Scope => self.scope(cx),
                    })),
            )
            .when_some(self.toast.clone(), |view, toast| {
                view.child(
                    div()
                        .absolute()
                        .right(px(24.))
                        .bottom(px(24.))
                        .max_w(px(520.))
                        .px_4()
                        .py_3()
                        .rounded_lg()
                        .bg(rgb(0x223046))
                        .border_1()
                        .border_color(rgb(0x39506d))
                        .shadow_lg()
                        .text_sm()
                        .text_color(rgb(TEXT))
                        .child(toast),
                )
            })
    }
}

fn section(title: &str, value: String) -> AnyElement {
    div()
        .child(section_title(title))
        .child(div().text_sm().text_color(rgb(TEXT)).child(value))
        .into_any_element()
}

fn section_title(title: &str) -> AnyElement {
    div()
        .mb_2()
        .text_xs()
        .font_weight(FontWeight::BOLD)
        .text_color(rgb(MUTED))
        .child(title.to_string())
        .into_any_element()
}

fn tier_style(tier: Tier) -> (&'static str, u32) {
    match tier {
        Tier::Safe => ("SAFE", ACCENT),
        Tier::Review => ("REVIEW", AMBER),
        Tier::Protected => ("PROTECTED", RED),
        Tier::Unknown => ("UNKNOWN", VIOLET),
    }
}

fn darken(color: u32) -> u32 {
    match color {
        ACCENT => ACCENT_DARK,
        AMBER => 0x3a2f1c,
        RED => 0x351f25,
        _ => 0x2b2441,
    }
}

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
