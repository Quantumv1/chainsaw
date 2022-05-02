use std::collections::HashSet;

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

// TODO: Bin me
pub fn format_field_length(mut data: String, full_output: bool, length: usize) -> String {
    // Take the context_field and format it for printing. Remove newlines, break into even chunks etc.
    // If this is a scheduled task we need to parse the XML to make it more readable

    data = data
        .replace("\n", "")
        .replace("\r", "")
        .replace("\t", "")
        .replace("  ", " ")
        .chars()
        .collect::<Vec<char>>()
        .chunks(length)
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

// TODO: Bin me
pub fn print_hunt_results(detections: &[Detection]) {
    // Create a unique list of all hunt result titles so that we can aggregate
    let detection_titles: HashSet<String> = detections.iter().map(|x| x.title.clone()).collect();
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
    // Loop through uniq list of hunt results
    for title in detection_titles {
        let mut table = Table::new();
        table.set_format(format);
        let mut header = false;
        cs_greenln!("\n[+] Detection: {}", title);

        let mut unsorted_rows = vec![];
        // Loop through detection values and print in a table view
        for detection in detections {
            // Only group together results of the same hunt
            if detection.title != *title {
                continue;
            }
            if !header {
                // Header builder
                let mut headers = vec![];
                for c in &detection.headers {
                    let cell = cell!(c).style_spec("c");
                    headers.push(cell);
                }
                table.add_row(Row::new(headers));
                header = true;
            }
            // Values builder
            let mut values = vec![];
            for c in &detection.values {
                values.push(c);
            }
            unsorted_rows.push(values);
        }

        // Sort by timestamp to get into acending order
        unsorted_rows.sort_by(|a, b| a.first().cmp(&b.first()));

        // This code block loops through rows and formats them into the prettytable-rs format
        // I think this can be simplified down the line
        let mut sorted_rows = vec![];
        for row in &unsorted_rows {
            let mut values = vec![];
            for item in row {
                values.push(cell!(item));
            }
            sorted_rows.push(values)
        }

        for row in sorted_rows {
            table.add_row(Row::new(row));
        }
        cs_print_table!(table);
    }
}
