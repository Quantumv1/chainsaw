use std::collections::HashMap;
use std::fs::{metadata, File};
use std::path::{Path, PathBuf};

use chrono::{DateTime, FixedOffset, NaiveDateTime};
use evtx::{EvtxParser, ParserSettings, SerializedEvtxRecord};
#[cfg(windows)]
use is_elevated::is_elevated as user_is_elevated;
use regex::Regex;
use serde_json::Value as Json;
use tau_engine::{AsValue, Document, Value as Tau};
use walkdir::WalkDir;

use crate::hunt::{Hit, Huntable, Mapping};
use crate::rule::Rule;

enum Provider {
    Defender,
    EventLogAction,
    FSecure,
    Kaspersky,
    SecurityAuditing,
    ServiceControl,
    Sophos,
}

impl Provider {
    fn resolve(provider: Option<Tau>) -> Option<Provider> {
        if let Some(p) = provider {
            if let Some(s) = p.as_str() {
                return match s {
                    "F-Secure Ultralight SDK" => Some(Provider::FSecure),
                    "Microsoft-Windows-Eventlog" => Some(Provider::EventLogAction),
                    "Microsoft-Windows-Security-Auditing" => Some(Provider::SecurityAuditing),
                    "Microsoft-Windows-Windows Defender" => Some(Provider::Defender),
                    "OnDemandScan" => Some(Provider::Kaspersky),
                    "Real-time file protection" => Some(Provider::Kaspersky),
                    "Service Control Manager" => Some(Provider::ServiceControl),
                    "Sophos Anti-Virus" => Some(Provider::Sophos),
                    _ => None,
                };
            }
        }
        None
    }
}

pub struct Wrapper<'a>(&'a HashMap<String, String>, &'a Json);
impl<'a> Document for Wrapper<'a> {
    fn find(&self, key: &str) -> Option<Tau<'_>> {
        self.0.get(key).and_then(|v| self.1.find(v))
    }
}

impl Huntable for SerializedEvtxRecord<Json> {
    fn created(&self) -> crate::Result<NaiveDateTime> {
        match NaiveDateTime::parse_from_str(
            self.data["Event"]["System"]["TimeCreated_attributes"]["SystemTime"]
                .as_str()
                .unwrap(),
            "%Y-%m-%dT%H:%M:%S%.6fZ",
        ) {
            Ok(t) => Ok(t),
            Err(_) => anyhow::bail!(
                "Failed to parse datetime from supplied events. This shouldn't happen..."
            ),
        }
    }

    fn hits(&self, rules: &[Rule], mapping: Option<&Mapping>) -> Option<Vec<Hit>> {
        match mapping {
            Some(mapping) => {
                // Event logs are a PITA, they can be inconsistent in their designs...
                let mut hits = vec![];
                for group in &mapping.groups {
                    let mut matched = false;
                    for filter in &group.filters {
                        for (k, v) in filter {
                            // TODO: Don't filter like this, its slow AF...
                            match k.as_str() {
                                "Event.System.EventID" => {
                                    if let Some(value) = self.data.find(k) {
                                        match (value.to_string(), v.as_value().to_string()) {
                                            (Some(x), Some(y)) => {
                                                matched = x == y;
                                            }
                                            (_, _) => {
                                                matched = false;
                                            }
                                        }
                                        if matched == false {
                                            break;
                                        }
                                        continue;
                                    } else if let Some(value) =
                                        self.data.find("Event.System.EventID.#text")
                                    {
                                        match (value.to_string(), v.as_value().to_string()) {
                                            (Some(x), Some(y)) => {
                                                matched = x == y;
                                            }
                                            (_, _) => {
                                                matched = false;
                                            }
                                        }
                                        if matched == false {
                                            break;
                                        }
                                        continue;
                                    }
                                }
                                "Event.System.Provider" => {
                                    if let Some(value) =
                                        self.data.find("Event.System.Provider_attributes.Name")
                                    {
                                        match (value.to_string(), v.as_value().to_string()) {
                                            (Some(x), Some(y)) => {
                                                matched = x == y;
                                            }
                                            (_, _) => {
                                                matched = false;
                                            }
                                        }
                                        if matched == false {
                                            break;
                                        }
                                        continue;
                                    }
                                }
                                _ => {
                                    if let Some(value) = self.data.find(k) {
                                        match (value.to_string(), v.as_value().to_string()) {
                                            (Some(x), Some(y)) => {
                                                matched = x == y;
                                            }
                                            (_, _) => {
                                                matched = false;
                                            }
                                        }
                                        if matched == false {
                                            break;
                                        }
                                        continue;
                                    }
                                }
                            }
                            matched = false;
                            break;
                        }
                        if matched {
                            break;
                        }
                    }
                    if matched {
                        for rule in rules {
                            if mapping.exclusions.contains(&rule.tag) {
                                continue;
                            }
                            if rule.tau.matches(&Wrapper(&group.fields, &self.data)) {
                                hits.push(Hit {
                                    tag: rule.tag.clone(),
                                    group: Some(group.name.clone()),
                                });
                            }
                        }
                    }
                }
                Some(hits)
            }
            None => {
                let mut hits = vec![];
                for rule in rules {
                    if rule.tau.matches(&self.data) {
                        hits.push(Hit {
                            tag: rule.tag.clone(),
                            group: None,
                        });
                    }
                }
                Some(hits)
            }
        }
    }
}

// TODO: Remove
pub fn get_files(mut path: &Path) -> crate::Result<Vec<PathBuf>> {
    let mut evtx_files: Vec<PathBuf> = Vec::new();
    if path.display().to_string() == *"win_default" {
        #[cfg(windows)]
        if !user_is_elevated() {
            return Err(anyhow!(
                "Cannot access local event logs - you are not running in an elevated session!"
            ));
        }
        path = Path::new("C:\\Windows\\System32\\winevt\\Logs\\");
    };
    if path.exists() {
        let md = metadata(&path)?;
        if md.is_dir() {
            // Grab files from within the specified directory
            // Check that the file ends in evtx
            for file in WalkDir::new(path) {
                let file_a = file?;
                if let Some(x) = file_a.path().extension() {
                    if x == "evtx" {
                        evtx_files.push(file_a.into_path());
                    }
                }
            }
        } else {
            evtx_files = vec![path.to_path_buf()];
        }
    } else {
        return Err(anyhow!("Invalid input path: {}", path.display()));
    };
    // Check if there is at least one EVTX file in the directory
    if !evtx_files.is_empty() {
        cs_eprintln!("[+] Found {} EVTX files", evtx_files.len());
    } else {
        return Err(anyhow!("No EVTx files found. Check input path?"));
    }
    Ok(evtx_files)
}

// TODO: Remove
pub fn parse_file(evtx_file: &Path) -> crate::Result<EvtxParser<File>> {
    let settings = ParserSettings::default()
        .separate_json_attributes(true)
        .num_threads(0);
    let parser = EvtxParser::from_path(evtx_file)?.with_configuration(settings);
    Ok(parser)
}

// TODO: Remove
pub fn search(
    mut parser: EvtxParser<File>,
    pattern: &Option<String>,
    regexp: &Option<Regex>,
    first: bool,
    from: Option<NaiveDateTime>,
    to: Option<NaiveDateTime>,
    event_id: Option<u32>,
    ignore_case: bool,
    json: bool,
) -> crate::Result<usize> {
    let mut hits = 0;

    for record in parser.records_json_value() {
        // TODO - work out why chunks of a record can fail here, but the overall event logs count
        // isn't affected. If this parser isn't seeing an event that you know exists, it's mostly
        // likely due to this match block
        let r = match record {
            Ok(record) => record,
            Err(_) => {
                continue;
            }
        };

        // Perform start/end datetime filtering
        if from.is_some() || to.is_some() {
            let event_time = match NaiveDateTime::parse_from_str(
                r.data["Event"]["System"]["TimeCreated_attributes"]["SystemTime"]
                    .as_str()
                    .unwrap(),
                "%Y-%m-%dT%H:%M:%S%.6fZ",
            ) {
                Ok(t) => t,
                Err(_) => {
                    return Err(anyhow!(
                        "Failed to parse datetime from supplied events. This shouldn't happen..."
                    ));
                }
            };

            // Check if event is older than start date marker
            if let Some(sd) = from {
                if event_time <= sd {
                    continue;
                }
            }
            // Check if event is newer than end date marker
            if let Some(ed) = to {
                if event_time >= ed {
                    continue;
                }
            }
        }
        // Do processing of EVTX record now it's in a JSON format
        //
        // The default action of the whole OK logic block it mark a record as matched
        // If a filter criteria is NOT matched, then we contiue the loop and don't push the
        // Record onto the matched records array

        // EventIDs can be stored in two different locations
        let eevent_id;
        if r.data["Event"]["System"]["EventID"]["#text"].is_null() {
            eevent_id = &r.data["Event"]["System"]["EventID"];
        } else {
            eevent_id = &r.data["Event"]["System"]["EventID"]["#text"];
        }

        // Handle event_id search option
        if let Some(e_id) = event_id {
            if eevent_id != e_id {
                continue;
            }
        };

        if let Some(ref re) = regexp {
            if !re.is_match(&r.data.to_string()) {
                continue;
            }
        } else if let Some(ref p) = pattern {
            if ignore_case {
                // Case insensitive string search
                if !r
                    .data
                    .to_string()
                    .to_lowercase()
                    .contains(&p.to_lowercase())
                {
                    continue;
                }
            } else {
                // Case sensitive search
                if !r.data.to_string().contains(p) {
                    continue;
                }
            }
        } else {
            continue;
        }

        if json {
            if !(first && hits == 0) {
                cs_print!(",");
            }
            cs_print_json!(&r.data)?;
        } else {
            cs_print_yaml!(&r.data)?;
        }

        hits += 1;
    }
    Ok(hits)
}
