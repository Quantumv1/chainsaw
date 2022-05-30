use std::collections::{HashMap, HashSet};

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use prettytable::{cell, format, Row, Table};
use tau_engine::Document;

use crate::hunt::{Detections, Kind, Mapping};
use crate::rule::Rule;

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

pub fn print_detections(
    detections: &[Detections],
    mappings: &[Mapping],
    rules: &[Rule],
    column_width: u32,
) {
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

    let mappings: HashMap<_, HashMap<_, _>> = mappings
        .iter()
        .map(|m| (&m.name, m.groups.iter().map(|g| (&g.name, g)).collect()))
        .collect();
    let rules: HashMap<_, _> = rules.iter().map(|r| (&r.tag, r)).collect();

    let empty = "".to_owned();
    let mut tables: HashMap<&String, (Row, Vec<Row>)> = HashMap::new();
    for detection in detections {
        let document = match &detection.kind {
            Kind::Individual { document } => document,
            _ => continue,
        };
        if let Some(mapping) = &detection.mapping {
            if let Some(groups) = mappings.get(mapping) {
                for hit in &detection.hits {
                    let group = groups
                        .get(&hit.group.as_ref().expect("group is not set!"))
                        .expect("could not get group!");
                    let mut header = vec![
                        cell!("timestamp").style_spec("c"),
                        cell!("detections").style_spec("c"),
                    ];
                    let mut cells = vec![
                        cell!(detection.timestamp),
                        cell!(detection
                            .hits
                            .iter()
                            .map(|h| h.tag.as_str())
                            .collect::<Vec<_>>()
                            .join("\n")),
                    ];
                    if let Some(default) = group.default.as_ref() {
                        for field in default {
                            header.push(cell!(field).style_spec("c"));
                            if let Some(value) = group
                                .fields
                                .get(field)
                                .and_then(|k| document.data.find(k))
                                .and_then(|v| v.to_string())
                            {
                                cells.push(cell!(format_field_length(&value, false, column_width)));
                            } else {
                                cells.push(cell!(""));
                            }
                        }
                    } else {
                        header.push(cell!("data").style_spec("c"));
                        let json = serde_json::to_string(&document.data)
                            .expect("could not serialise document");
                        cells.push(cell!(format_field_length(&json, false, column_width)));
                    }
                    let table = tables
                        .entry(&group.name)
                        .or_insert((Row::new(header), vec![]));
                    (*table).1.push(Row::new(cells));
                }
            }
        } else {
            let mut cells = vec![
                cell!(detection.timestamp),
                cell!(detection
                    .hits
                    .iter()
                    .map(|h| h.tag.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")),
            ];
            let json = serde_json::to_string(&document.data).expect("could not serialise document");
            cells.push(cell!(format_field_length(&json, false, column_width)));
            let rows = tables.entry(&empty).or_insert((
                Row::new(vec![
                    cell!("timestamp").style_spec("c"),
                    cell!("detections").style_spec("c"),
                    cell!("data").style_spec("c"),
                ]),
                vec![],
            ));
            (*rows).1.push(Row::new(cells));
        }
    }

    let mut keys = tables.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        let table = tables.remove(key).expect("could not get table!");
        let mut t = Table::new();
        t.set_format(format);
        t.add_row(table.0);
        for row in table.1 {
            t.add_row(row);
        }
        cs_greenln!("\n[+] Group: {}", key);
        cs_print_table!(t);
    }
}
