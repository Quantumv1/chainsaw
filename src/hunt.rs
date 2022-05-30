use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

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

#[derive(Debug, Serialize)]
pub struct Detection {
    pub authors: Vec<String>,
    pub group: String,
    #[serde(flatten)]
    pub kind: Kind,
    pub level: String,
    pub rule: String,
    pub status: String,
    pub tag: String,
    pub timestamp: NaiveDateTime,
}

#[derive(Debug, Serialize)]
pub struct Document {
    pub kind: String,
    pub data: Json,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Kind {
    Aggregate { documents: Vec<Document> },
    Individual { document: Document },
}

pub trait Huntable {
    fn created(&self) -> crate::Result<NaiveDateTime>;
    fn tags(&self, mapping: &Mapping, rules: &[Rule]) -> Option<Vec<String>>;
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
            Some(rules) => rules.into_iter().map(|r| (r.tag.clone(), r)).collect(),
            None => HashMap::new(),
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
    rules: HashMap<String, Rule>,

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
        // TODO: We probably want to abstract this?
        let mut parser = match evtx::parse_file(file) {
            Ok(a) => a,
            Err(e) => {
                if self.inner.skip_errors {
                    return Ok(vec![]);
                }
                anyhow::bail!("{:?} - {}", file, e);
            }
        };
        // TODO: Remove this...
        let rules: Vec<_> = self.inner.rules.values().cloned().collect();
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
                let time = DateTime::<Utc>::from_utc(event_time, Utc);
                // Check if event is older than start date marker
                if let Some(sd) = self.inner.from {
                    if time <= sd {
                        continue;
                    }
                }
                // Check if event is newer than end date marker
                if let Some(ed) = self.inner.to {
                    if time >= ed {
                        continue;
                    }
                }
            }

            //
            for mapping in &self.inner.mappings {
                if let Some(tags) = r.tags(&mapping, &rules) {
                    // FIXME: This is a temp way to get the group...
                    let event_id = if r.data["Event"]["System"]["EventID"]["#text"].is_null() {
                        r.data["Event"]["System"]["EventID"].as_u64()
                    } else {
                        r.data["Event"]["System"]["EventID"]["#text"].as_u64()
                    };
                    let event = mapping.events.get(&event_id.unwrap()).unwrap();

                    // FIXME: This will bloat memory, we should store compressed then explode on write
                    // out...
                    for tag in tags {
                        let rule = self.inner.rules.get(&tag).unwrap();
                        detections.push(Detection {
                            authors: rule.authors.as_ref().unwrap().clone(),
                            group: event.title.clone(),
                            kind: Kind::Individual {
                                document: Document {
                                    kind: "evtx".to_owned(),
                                    data: r.data.clone(),
                                },
                            },
                            level: rule.level.as_ref().unwrap().clone(),
                            rule: "sigma".to_owned(),
                            status: rule.status.as_ref().unwrap().clone(),
                            tag: rule.tag.clone(),
                            timestamp: r.created().unwrap(),
                        });
                    }
                }
            }
        }
        Ok(detections)
    }

    pub fn mappings(&self) -> &Vec<Mapping> {
        &self.inner.mappings
    }
}
