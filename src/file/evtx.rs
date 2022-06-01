use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::Path;

use chrono::NaiveDateTime;
use evtx::{err::EvtxError, EvtxParser, ParserSettings, SerializedEvtxRecord};
use regex::Regex;
use serde_json::Value as Json;
use tau_engine::{AsValue, Document, Value as Tau};

use crate::hunt::{Group, Huntable};
use crate::rule::Rule;
use crate::search::Searchable;

pub type Evtx = SerializedEvtxRecord<Json>;

pub struct Parser {
    pub inner: EvtxParser<File>,
}

impl Parser {
    pub fn load(file: &Path) -> crate::Result<Self> {
        let settings = ParserSettings::default()
            .separate_json_attributes(true)
            .num_threads(0);
        let parser = EvtxParser::from_path(file)?.with_configuration(settings);
        Ok(Self { inner: parser })
    }

    pub fn parse(
        &mut self,
    ) -> impl Iterator<Item = Result<SerializedEvtxRecord<serde_json::Value>, EvtxError>> + '_ {
        self.inner.records_json_value()
    }
}

pub struct Mapper<'a>(&'a HashMap<String, String>, &'a Json);
impl<'a> Document for Mapper<'a> {
    fn find(&self, key: &str) -> Option<Tau<'_>> {
        self.0.get(key).and_then(|v| self.1.find(v))
    }
}

impl Huntable for &SerializedEvtxRecord<Json> {
    fn hits(
        &self,
        rules: &[Rule],
        exclusions: &HashSet<String>,
        group: &Group,
    ) -> Option<Vec<String>> {
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
                        } else if let Some(value) = self.data.find("Event.System.EventID.#text") {
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
                        if let Some(value) = self.data.find("Event.System.Provider_attributes.Name")
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
            let mut tags = vec![];
            for rule in rules {
                if exclusions.contains(&rule.tag) {
                    continue;
                }
                if rule.tau.matches(&Mapper(&group.fields, &self.data)) {
                    tags.push(rule.tag.clone());
                }
            }
            return Some(tags);
        }
        None
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
