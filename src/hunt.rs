use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::file::{Document as Doc, Reader};
use crate::rule::{Kind as RuleKind, Rule};

#[derive(Deserialize)]
pub struct Group {
    #[serde(default)]
    pub default: Option<Vec<String>>,
    pub fields: HashMap<String, String>,
    pub filters: Vec<HashMap<String, Json>>,
    pub name: String,
}

#[derive(Deserialize)]
pub struct Mapping {
    #[serde(default)]
    pub exclusions: HashSet<String>,
    pub groups: Vec<Group>,
    pub kind: String,
    pub name: String,
    pub rules: RuleKind,
}

pub struct Hit {
    pub tag: String,
    pub group: Option<String>,
}

pub struct Detections {
    pub hits: Vec<Hit>,
    pub kind: Kind,
    pub mapping: Option<String>,
    pub timestamp: NaiveDateTime,
}

#[derive(Debug, Serialize)]
pub struct Detection<'a> {
    pub authors: &'a Vec<String>,
    pub group: &'a Option<String>,
    #[serde(flatten)]
    pub kind: &'a Kind,
    pub level: &'a String,
    pub name: &'a String,
    pub ruleset: &'a String,
    pub status: &'a String,
    pub timestamp: &'a NaiveDateTime,
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
    fn hits(&self, rules: &[Rule], mapping: Option<&Mapping>) -> Option<Vec<Hit>>;
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

    pub fn hunt(&self, file: &Path) -> crate::Result<Vec<Detections>> {
        let mut reader = Reader::load(file)?;
        let mut detections = vec![];
        for document in reader.documents() {
            let document = match document {
                Ok(document) => document,
                Err(e) => {
                    if self.inner.skip_errors {
                        continue;
                    }
                    return Err(e);
                }
            };

            let timestamp = match &document {
                Doc::Evtx(evtx) => match evtx.created() {
                    Ok(timestamp) => timestamp,
                    Err(e) => {
                        if self.inner.skip_errors {
                            continue;
                        }
                        anyhow::bail!("could not get timestamp - {}", e);
                    }
                },
            };

            if self.inner.from.is_some() || self.inner.to.is_some() {
                let localised = DateTime::<Utc>::from_utc(timestamp, Utc);
                // Check if event is older than start date marker
                if let Some(sd) = self.inner.from {
                    if localised <= sd {
                        continue;
                    }
                }
                // Check if event is newer than end date marker
                if let Some(ed) = self.inner.to {
                    if localised >= ed {
                        continue;
                    }
                }
            }

            if self.inner.mappings.is_empty() {
                if let Some(hits) = match &document {
                    Doc::Evtx(evtx) => evtx.hits(&self.inner.rules, None),
                } {
                    if hits.is_empty() {
                        continue;
                    }
                    let data = match document {
                        Doc::Evtx(evtx) => evtx.data,
                    };
                    detections.push(Detections {
                        hits,
                        kind: Kind::Individual {
                            document: Document {
                                kind: "evtx".to_owned(),
                                data,
                            },
                        },
                        mapping: None,
                        timestamp,
                    });
                }
            } else {
                for mapping in &self.inner.mappings {
                    if mapping.kind != "evtx" {
                        continue;
                    }
                    if let Some(hits) = match &document {
                        Doc::Evtx(evtx) => evtx.hits(&self.inner.rules, Some(&mapping)),
                    } {
                        if hits.is_empty() {
                            continue;
                        }
                        let data = match &document {
                            Doc::Evtx(evtx) => evtx.data.clone(),
                        };
                        detections.push(Detections {
                            hits,
                            kind: Kind::Individual {
                                document: Document {
                                    kind: "evtx".to_owned(),
                                    data,
                                },
                            },
                            mapping: Some(mapping.name.clone()),
                            timestamp,
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

    pub fn rules(&self) -> &Vec<Rule> {
        &self.inner.rules
    }
}
