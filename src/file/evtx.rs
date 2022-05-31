use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use chrono::NaiveDateTime;
use evtx::{EvtxParser, ParserSettings, SerializedEvtxRecord};
#[cfg(windows)]
use is_elevated::is_elevated as user_is_elevated;
use regex::Regex;
use serde_json::Value as Json;
use tau_engine::{AsValue, Document, Value as Tau};

use crate::hunt::{Hit, Huntable, Mapping};
use crate::rule::Rule;
use crate::search::Searchable;

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

impl Searchable for SerializedEvtxRecord<Json> {
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

    fn matches(&self, regex: &Option<Regex>, pattern: &Option<String>, ignore_case: bool) -> bool {
        if let Some(ref re) = regex {
            if !re.is_match(&self.data.to_string()) {
                return false;
            }
        } else if let Some(ref p) = pattern {
            if ignore_case {
                // Case insensitive string search
                if !self
                    .data
                    .to_string()
                    .to_lowercase()
                    .contains(&p.to_lowercase())
                {
                    return false;
                }
            } else {
                // Case sensitive search
                if !self.data.to_string().contains(p) {
                    return false;
                }
            }
        } else {
            return false;
        }
        true
    }
}

// TODO: Remove
pub fn parse_file(evtx_file: &Path) -> crate::Result<EvtxParser<File>> {
    let settings = ParserSettings::default()
        .separate_json_attributes(true)
        .num_threads(0);
    let parser = EvtxParser::from_path(evtx_file)?.with_configuration(settings);
    Ok(parser)
}
