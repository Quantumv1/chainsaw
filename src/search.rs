use std::fs::File;
use std::path::Path;

use ::evtx::{EvtxParser, SerializedEvtxRecord};
use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;
use serde_json::Value as Json;

use crate::file::evtx;

pub struct Hits<'a> {
    parser: EvtxParser<File>,
    searcher: &'a SearcherInner,
}

impl<'a> Hits<'a> {
    pub fn iter(&mut self) -> HitsIter<'_> {
        HitsIter {
            it: Box::new(self.parser.records_json_value()),
            searcher: self.searcher,
        }
    }
}

pub struct HitsIter<'b> {
    it: Box<
        dyn Iterator<Item = Result<SerializedEvtxRecord<serde_json::Value>, ::evtx::err::EvtxError>>
            + 'b,
    >,
    searcher: &'b SearcherInner,
}

impl<'a> Iterator for HitsIter<'a> {
    type Item = crate::Result<Json>;

    fn next(&mut self) -> Option<crate::Result<Json>> {
        while let Some(record) = self.it.next() {
            let r = match record {
                Ok(record) => record,
                Err(_) => {
                    continue;
                }
            };
            let timestamp = match r.created() {
                Ok(timestamp) => timestamp,
                Err(e) => {
                    if self.searcher.skip_errors {
                        continue;
                    }
                    return Some(Err(anyhow!("could not get timestamp - {}", e)));
                }
            };
            if self.searcher.from.is_some() || self.searcher.to.is_some() {
                let localised = DateTime::<Utc>::from_utc(timestamp, Utc);
                // Check if event is older than start date marker
                if let Some(sd) = self.searcher.from {
                    if localised <= sd {
                        continue;
                    }
                }
                // Check if event is newer than end date marker
                if let Some(ed) = self.searcher.to {
                    if localised >= ed {
                        continue;
                    }
                }
            }
            // TODO: Remove me
            let event_id = if r.data["Event"]["System"]["EventID"]["#text"].is_null() {
                &r.data["Event"]["System"]["EventID"]
            } else {
                &r.data["Event"]["System"]["EventID"]["#text"]
            };
            if let Some(e_id) = self.searcher.event_id {
                if event_id != e_id {
                    continue;
                }
            };

            if r.matches(
                &self.searcher.regex,
                &self.searcher.pattern,
                self.searcher.ignore_case,
            ) {
                return Some(Ok(r.data));
            }
        }
        None
    }
}

pub trait Searchable {
    fn created(&self) -> crate::Result<NaiveDateTime>;
    fn matches(&self, regex: &Option<Regex>, pattern: &Option<String>, ignore_case: bool) -> bool;
}

#[derive(Default)]
pub struct SearcherBuilder {
    event_id: Option<u32>,
    pattern: Option<String>,
    regex: Option<Regex>,

    from: Option<NaiveDateTime>,
    ignore_case: Option<bool>,
    skip_errors: Option<bool>,
    to: Option<NaiveDateTime>,
}

impl SearcherBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> crate::Result<Searcher> {
        let ignore_case = self.ignore_case.unwrap_or_default();
        let skip_errors = self.skip_errors.unwrap_or_default();

        Ok(Searcher {
            inner: SearcherInner {
                event_id: self.event_id,
                pattern: self.pattern,
                regex: self.regex,

                from: self.from.map(|d| DateTime::from_utc(d, Utc)),
                ignore_case,
                skip_errors,
                to: self.to.map(|d| DateTime::from_utc(d, Utc)),
            },
        })
    }

    pub fn event_id(mut self, event_id: u32) -> Self {
        self.event_id = Some(event_id);
        self
    }

    pub fn from(mut self, datetime: NaiveDateTime) -> Self {
        self.from = Some(datetime);
        self
    }

    pub fn ignore_case(mut self, ignore: bool) -> Self {
        self.ignore_case = Some(ignore);
        self
    }

    pub fn pattern(mut self, pattern: String) -> Self {
        self.pattern = Some(pattern);
        self
    }

    pub fn regex(mut self, regex: Regex) -> Self {
        self.regex = Some(regex);
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

pub struct SearcherInner {
    event_id: Option<u32>,
    pattern: Option<String>,
    regex: Option<Regex>,

    from: Option<DateTime<Utc>>,
    ignore_case: bool,
    skip_errors: bool,
    to: Option<DateTime<Utc>>,
}

pub struct Searcher {
    inner: SearcherInner,
}

impl Searcher {
    pub fn builder() -> SearcherBuilder {
        SearcherBuilder::new()
    }

    pub fn search(&self, file: &Path) -> crate::Result<Hits> {
        // TODO: We probably want to abstract this?
        let parser = match evtx::parse_file(file) {
            Ok(a) => a,
            Err(e) => {
                //if self.inner.skip_errors {
                //    return Ok(vec![]);
                //}
                anyhow::bail!("{:?} - {}", file, e);
            }
        };
        Ok(Hits {
            parser,
            searcher: &self.inner,
        })
    }
}
