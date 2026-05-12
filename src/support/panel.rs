use owo_colors::OwoColorize;
use std::io::{IsTerminal, Write};
use std::sync::{Mutex, OnceLock};

const MIN_WIDTH: usize = 60;
const MAX_WIDTH: usize = 120;
const DEFAULT_WIDTH: usize = 80;

static CACHED_WIDTH: OnceLock<usize> = OnceLock::new();

pub fn width() -> usize {
    *CACHED_WIDTH.get_or_init(|| {
        let cols = terminal_size::terminal_size()
            .map(|(terminal_size::Width(w), _)| w as usize)
            .unwrap_or(DEFAULT_WIDTH);
        cols.clamp(MIN_WIDTH, MAX_WIDTH)
    })
}

struct ProgressState {
    badge: String,
    brand: String,
    left: String,
    tty: bool,
}

static PROGRESS: Mutex<Option<ProgressState>> = Mutex::new(None);

pub fn progress(msg: &str) {
    let state = PROGRESS.lock().unwrap();
    let Some(s) = state.as_ref() else {
        eprintln!("  {} {}", "→".bright_black(), msg.bright_black());
        return;
    };
    if !s.tty {
        eprintln!("  {} {}", "→".bright_black(), msg.bright_black());
        return;
    }
    rewrite_header_right(s, msg);
}

pub fn finish_progress(final_right: &str) {
    let mut state = PROGRESS.lock().unwrap();
    if let Some(s) = state.as_ref()
        && s.tty
    {
        rewrite_header_right(s, final_right);
    }
    *state = None;
}

fn rewrite_header_right(s: &ProgressState, right: &str) {
    let inner = width() - 2;
    let used = 2
        + s.badge.chars().count()
        + 1
        + s.brand.chars().count()
        + 3
        + s.left.chars().count()
        + right.chars().count()
        + 2;
    let pad = inner.saturating_sub(used);
    let row = format!(
        "  {} {} {} {}{}{}  ",
        accent_bold(&s.badge),
        text_bold(&s.brand),
        muted("·"),
        text_bold(&s.left),
        " ".repeat(pad),
        muted(right),
    );
    print!(
        "\x1b[3A\r\x1b[2K{}{}{}\x1b[3B\r",
        border("│"),
        row,
        border("│"),
    );
    std::io::stdout().flush().ok();
}

const BORDER_RGB: (u8, u8, u8) = (38, 50, 68);
const TEXT_RGB: (u8, u8, u8) = (229, 231, 235);
const MUTED_RGB: (u8, u8, u8) = (124, 132, 151);
const SUCCESS_RGB: (u8, u8, u8) = (126, 231, 135);
const WARNING_RGB: (u8, u8, u8) = (242, 204, 96);
const DANGER_RGB: (u8, u8, u8) = (255, 107, 154);
const INFO_RGB: (u8, u8, u8) = (138, 180, 255);
const ACCENT_RGB: (u8, u8, u8) = (192, 132, 252);

pub fn border(s: &str) -> String {
    s.truecolor(BORDER_RGB.0, BORDER_RGB.1, BORDER_RGB.2).to_string()
}
pub fn text(s: &str) -> String {
    s.truecolor(TEXT_RGB.0, TEXT_RGB.1, TEXT_RGB.2).to_string()
}
pub fn text_bold(s: &str) -> String {
    s.truecolor(TEXT_RGB.0, TEXT_RGB.1, TEXT_RGB.2).bold().to_string()
}
pub fn muted(s: &str) -> String {
    s.truecolor(MUTED_RGB.0, MUTED_RGB.1, MUTED_RGB.2).to_string()
}
pub fn success(s: &str) -> String {
    s.truecolor(SUCCESS_RGB.0, SUCCESS_RGB.1, SUCCESS_RGB.2).to_string()
}
pub fn success_bold(s: &str) -> String {
    s.truecolor(SUCCESS_RGB.0, SUCCESS_RGB.1, SUCCESS_RGB.2).bold().to_string()
}
pub fn warning(s: &str) -> String {
    s.truecolor(WARNING_RGB.0, WARNING_RGB.1, WARNING_RGB.2).to_string()
}
pub fn warning_bold(s: &str) -> String {
    s.truecolor(WARNING_RGB.0, WARNING_RGB.1, WARNING_RGB.2).bold().to_string()
}
pub fn danger(s: &str) -> String {
    s.truecolor(DANGER_RGB.0, DANGER_RGB.1, DANGER_RGB.2).to_string()
}
pub fn danger_bold(s: &str) -> String {
    s.truecolor(DANGER_RGB.0, DANGER_RGB.1, DANGER_RGB.2).bold().to_string()
}
pub fn info(s: &str) -> String {
    s.truecolor(INFO_RGB.0, INFO_RGB.1, INFO_RGB.2).to_string()
}
pub fn accent(s: &str) -> String {
    s.truecolor(ACCENT_RGB.0, ACCENT_RGB.1, ACCENT_RGB.2).to_string()
}
pub fn accent_bold(s: &str) -> String {
    s.truecolor(ACCENT_RGB.0, ACCENT_RGB.1, ACCENT_RGB.2).bold().to_string()
}

#[derive(Default)]
pub struct Line {
    pub visible: usize,
    pub rendered: String,
}

impl Line {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn raw(mut self, vis: &str, rendered: &str) -> Self {
        self.visible += vis.chars().count();
        self.rendered.push_str(rendered);
        self
    }
    pub fn space(self, n: usize) -> Self {
        let s = " ".repeat(n);
        self.raw(&s.clone(), &s)
    }
    pub fn plain(self, s: &str) -> Self {
        let r = s.to_string();
        self.raw(s, &r)
    }
    pub fn styled(self, s: &str, f: impl FnOnce(&str) -> String) -> Self {
        let r = f(s);
        self.raw(s, &r)
    }
}

pub fn top_titled(title: &str, badge: &str) {
    let prefix_visible = format!("╭─ {} ", badge);
    let title_visible = title.to_string();
    let used = prefix_visible.chars().count() + title_visible.chars().count() + 1;
    let dashes = width().saturating_sub(used + 1);
    println!(
        "{}{}{}{}",
        border("╭─ "),
        accent_bold(badge),
        format!(" {} ", text_bold(title)),
        border(&format!("{}─╮", "─".repeat(dashes))),
    );
}

pub fn top_section(label: &str) {
    let prefix_visible = format!("╭─ {} ", label);
    let used = prefix_visible.chars().count();
    let dashes = width().saturating_sub(used + 1);
    println!(
        "{}{}{}",
        border("╭─ "),
        text_bold(label),
        border(&format!(" {}╮", "─".repeat(dashes))),
    );
}

pub fn bottom() {
    println!("{}", border(&format!("╰{}╯", "─".repeat(width() - 2))));
}

pub fn blank() {
    let inner = width() - 2;
    println!("{}{}{}", border("│"), " ".repeat(inner), border("│"));
}

pub fn row(line: Line) {
    let inner = width() - 2;
    let pad = inner.saturating_sub(line.visible);
    println!("{}{}{}{}", border("│"), line.rendered, " ".repeat(pad), border("│"));
}

pub fn divider() {
    let inner = width() - 2;
    let dashes = inner - 2;
    println!(
        "{}{}{}",
        border("│"),
        border(&format!(" {} ", "─".repeat(dashes))),
        border("│"),
    );
}

pub fn header_panel(badge: &str, brand: &str, left: &str, right: &str) {
    println!();
    println!("{}", border(&format!("╭{}╮", "─".repeat(width() - 2))));
    let inner = width() - 2;
    let used = 2
        + badge.chars().count()
        + 1
        + brand.chars().count()
        + 3
        + left.chars().count()
        + right.chars().count()
        + 2;
    let pad = inner.saturating_sub(used);
    let rendered = format!(
        "  {} {} {} {}{}{}  ",
        accent_bold(badge),
        text_bold(brand),
        muted("·"),
        text_bold(left),
        " ".repeat(pad),
        muted(right),
    );
    println!("{}{}{}", border("│"), rendered, border("│"));
    bottom();
    println!();

    let mut state = PROGRESS.lock().unwrap();
    *state = Some(ProgressState {
        badge: badge.into(),
        brand: brand.into(),
        left: left.into(),
        tty: std::io::stdout().is_terminal(),
    });
    drop(state);
    progress(right);
}

pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.chars().count() + 1 + word.chars().count() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_breaks_on_word_boundaries() {
        let lines = wrap("the quick brown fox jumps", 10);
        assert!(lines.iter().all(|l| l.chars().count() <= 10));
        assert_eq!(lines.join(" "), "the quick brown fox jumps");
    }

    #[test]
    fn line_tracks_visible_separately_from_rendered() {
        let l = Line::new().plain("hi").styled("X", |s| format!("\x1b[31m{s}\x1b[0m"));
        assert_eq!(l.visible, 3);
        assert!(l.rendered.contains("hi"));
        assert!(l.rendered.contains("\x1b[31m"));
    }
}
