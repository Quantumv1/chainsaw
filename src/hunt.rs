use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use serde::Deserialize;

use crate::file::evtx;
use crate::rule::{Kind as RuleKind, Rule};

#[derive(Debug, PartialEq, Deserialize)]
pub struct Events {
    pub provider: String,
    pub search_fields: HashMap<String, String>,
    pub table_headers: HashMap<String, String>,
    pub title: String,
}

#[derive(Debug, Deserialize)]
pub struct Mapping {
    #[serde(default)]
    pub exclusions: HashSet<String>,
    pub kind: RuleKind,
    #[serde(alias = "mappings")]
    pub events: HashMap<u64, Events>,
}

// TODO: Re-design
pub struct Detection {
    pub headers: Vec<String>,
    pub title: String,
    pub values: Vec<String>,
}

pub trait Huntable {
    fn created(&self) -> crate::Result<DateTime<FixedOffset>>;
    fn hunt(&self, mapping: &Mapping, rules: &Vec<Rule>) -> Option<Detection>;
}

#[derive(Default)]
pub struct HunterBuilder {
    mappings: Option<Vec<PathBuf>>,
    rules: Option<Vec<Rule>>,

    from: Option<NaiveDateTime>,
    skip_errors: Option<bool>,
    to: Option<NaiveDateTime>,
}

impl HunterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> crate::Result<Hunter> {
        let mappings = match self.mappings {
            Some(mappings) => {
                let mut scratch = vec![];
                for mapping in mappings {
                    let mut file = File::open(mapping)?;
                    let mut content = String::new();
                    file.read_to_string(&mut content)?;
                    scratch.push(serde_yaml::from_str(&mut content)?);
                }
                scratch
            }
            None => vec![],
        };
        let rules = match self.rules {
            Some(rules) => rules,
            None => vec![],
        };

        let skip_errors = self.skip_errors.unwrap_or_default();

        Ok(Hunter {
            inner: HunterInner {
                mappings,
                rules,

                from: self.from.map(|d| DateTime::from_utc(d, Utc)),
                skip_errors,
                to: self.to.map(|d| DateTime::from_utc(d, Utc)),
            },
        })
    }

    pub fn from(mut self, datetime: NaiveDateTime) -> Self {
        self.from = Some(datetime);
        self
    }

    pub fn mappings(mut self, paths: Vec<PathBuf>) -> Self {
        self.mappings = Some(paths);
        self
    }

    pub fn rules(mut self, rules: Vec<Rule>) -> Self {
        self.rules = Some(rules);
        self
    }

    pub fn skip_errors(mut self, skip: bool) -> Self {
        self.skip_errors = Some(skip);
        self
    }

    pub fn to(mut self, datetime: NaiveDateTime) -> Self {
        self.to = Some(datetime);
        self
    }
}

pub struct HunterInner {
    mappings: Vec<Mapping>,
    rules: Vec<Rule>,

    from: Option<DateTime<Utc>>,
    skip_errors: bool,
    to: Option<DateTime<Utc>>,
}

pub struct Hunter {
    inner: HunterInner,
}

impl Hunter {
    pub fn builder() -> HunterBuilder {
        HunterBuilder::new()
    }

    pub fn hunt(&self, file: &Path) -> crate::Result<Vec<Detection>> {
        let mut parser = match evtx::parse_file(file) {
            Ok(a) => a,
            Err(e) => {
                if self.inner.skip_errors {
                    return Ok(vec![]);
                }
                anyhow::bail!("{:?} - {}", file, e);
            }
        };
        let mut detections = vec![];
        for record in parser.records_json_value() {
            let r = match record {
                Ok(record) => record,
                Err(_) => {
                    continue;
                }
            };
            if self.inner.from.is_some() || self.inner.to.is_some() {
                // TODO: Handle this...
                let event_time = r.created().unwrap();
                // Check if event is older than start date marker
                if let Some(sd) = self.inner.from {
                    if event_time <= sd {
                        continue;
                    }
                }
                // Check if event is newer than end date marker
                if let Some(ed) = self.inner.to {
                    if event_time >= ed {
                        continue;
                    }
                }
            }

            //
            for mapping in &self.inner.mappings {
                if let Some(detection) = r.hunt(&mapping, &self.inner.rules) {
                    detections.push(detection);
                }
            }
        }
        Ok(detections)
    }
}
