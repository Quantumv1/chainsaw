use std::collections::{HashMap, HashSet};

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use prettytable::{cell, format, Row, Table};

use crate::hunt::Detection;

#[cfg(not(windows))]
pub const RULE_PREFIX: &str = "‣ ";

#[cfg(windows)]
pub const RULE_PREFIX: &str = "+ ";

#[cfg(not(windows))]
const TICK_SETTINGS: (&str, u64) = ("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ", 80);

#[cfg(windows)]
const TICK_SETTINGS: (&str, u64) = (r"-\|/-", 200);

pub fn init_progress_bar(size: u64, msg: String) -> indicatif::ProgressBar {
    let pb = ProgressBar::new(size);
    unsafe {
        match crate::write::WRITER.quiet {
            true => pb.set_draw_target(ProgressDrawTarget::hidden()),
            false => pb.set_draw_target(ProgressDrawTarget::stderr()),
        }
    };
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[+] {msg}: [{bar:40}] {pos}/{len} {spinner}")
            .tick_chars(TICK_SETTINGS.0)
            .progress_chars("=>-"),
    );

    pb.set_message(msg);
    pb.enable_steady_tick(TICK_SETTINGS.1);
    pb
}

pub fn format_field_length(data: &str, full_output: bool, length: u32) -> String {
    // Take the context_field and format it for printing. Remove newlines, break into even chunks etc.
    // If this is a scheduled task we need to parse the XML to make it more readable
    let mut data = data
        .replace("\n", "")
        .replace("\r", "")
        .replace("\t", "")
        .replace("  ", " ")
        .chars()
        .collect::<Vec<char>>()
        .chunks(length as usize)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join("\n");

    let truncate_len = 1000;

    if !full_output && data.len() > truncate_len {
        data.truncate(truncate_len);
        data.push_str("...\n\n(use --full to show all content)");
    }

    data
}

pub fn print_detections(detections: &[Detection], column_width: u32) {
    let format = format::FormatBuilder::new()
        .column_separator('│')
        .borders('│')
        .separators(
            &[format::LinePosition::Top],
            format::LineSeparator::new('─', '┬', '┌', '┐'),
        )
        .separators(
            &[format::LinePosition::Intern],
            format::LineSeparator::new('─', '┼', '├', '┤'),
        )
        .separators(
            &[format::LinePosition::Bottom],
            format::LineSeparator::new('─', '┴', '└', '┘'),
        )
        .padding(1, 1)
        .build();

    let mut tables: HashMap<&String, Vec<&Detection>> = HashMap::new();
    for detection in detections {
        let hits = tables.entry(&detection.group).or_insert(vec![]);
        (*hits).push(detection);
    }

    for (group, mut rows) in tables {
        let mut headers = vec![cell!("timestamp").style_spec("c")];
        let mut order = vec![];
        for c in rows[0].data.keys() {
            let cell = cell!(c).style_spec("c");
            headers.push(cell);
            order.push(c);
        }
        let mut table = Table::new();
        table.set_format(format);
        table.add_row(Row::new(headers));

        rows.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        for row in rows {
            let mut cells = vec![cell!(row.timestamp)];
            for key in &order {
                if let Some(value) = row.data.get(key.as_str()) {
                    cells.push(cell!(format_field_length(value, false, column_width)));
                } else {
                    cells.push(cell!(""));
                }
            }
            table.add_row(Row::new(cells));
        }
        cs_greenln!("\n[+] Detection: {}", group);
        cs_print_table!(table);
        break;
    }
}
