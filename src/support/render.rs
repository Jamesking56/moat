use owo_colors::OwoColorize;

pub struct Cell {
    pub visible: String,
    pub rendered: String,
}

impl Cell {
    pub fn plain(s: impl Into<String>) -> Self {
        let s = s.into();
        Self { rendered: s.clone(), visible: s }
    }

    pub fn styled(visible: impl Into<String>, rendered: impl Into<String>) -> Self {
        Self { visible: visible.into(), rendered: rendered.into() }
    }
}

pub fn render(headers: &[&str], rows: &[Vec<Cell>]) {
    let n = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().take(n).enumerate() {
            widths[i] = widths[i].max(cell.visible.chars().count());
        }
    }

    print!("  ");
    for (i, h) in headers.iter().enumerate() {
        if i > 0 {
            print!("  ");
        }
        let pad = widths[i].saturating_sub(h.chars().count());
        print!("{}{}", h.bold(), " ".repeat(pad));
    }
    println!();

    print!("  ");
    for (i, _) in headers.iter().enumerate() {
        if i > 0 {
            print!("  ");
        }
        print!("{}", "─".repeat(widths[i]).bright_black());
    }
    println!();

    for row in rows {
        print!("  ");
        for (i, cell) in row.iter().take(n).enumerate() {
            if i > 0 {
                print!("  ");
            }
            let pad = widths[i].saturating_sub(cell.visible.chars().count());
            print!("{}{}", cell.rendered, " ".repeat(pad));
        }
        println!();
    }
}

pub fn truncate(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        s.to_string()
    } else {
        let kept: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
    }
}
