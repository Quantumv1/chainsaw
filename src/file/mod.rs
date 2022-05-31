use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value as Json;
use walkdir::WalkDir;

use self::evtx::{Evtx, Parser as EvtxParser};

pub mod evtx;

pub enum Document {
    Evtx(Evtx),
}

pub struct Documents<'a> {
    iterator: Box<dyn Iterator<Item = crate::Result<Document>> + 'a>,
}

impl<'a> Iterator for Documents<'a> {
    type Item = crate::Result<Document>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iterator.next()
    }
}

pub enum Parser {
    Evtx(EvtxParser),
}

pub struct Reader {
    parser: Parser,
}

impl Reader {
    pub fn load(file: &Path) -> crate::Result<Self> {
        // NOTE: We don't want to use libmagic because then we have to include databases etc... So
        // for now we assume that the file extensions are correct!
        match file.extension().and_then(|e| e.to_str()) {
            Some(extension) => match extension {
                "evtx" => Ok(Self {
                    parser: Parser::Evtx(EvtxParser::load(file)?),
                }),
                _ => anyhow::bail!("file type is not currently supported - {}", extension),
            },
            None => anyhow::bail!("file type is not known"),
        }
    }

    pub fn documents<'a>(&'a mut self) -> Documents<'a> {
        let iterator = match &mut self.parser {
            Parser::Evtx(parser) => parser
                .parse()
                .map(|r| r.map(|d| Document::Evtx(d)).map_err(|e| e.into())),
        };
        Documents {
            iterator: Box::new(iterator),
        }
    }
}

pub fn get_files(path: &Path, extension: &Option<String>) -> crate::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = vec![];
    if path.exists() {
        let metadata = fs::metadata(&path)?;
        if metadata.is_dir() {
            for file in WalkDir::new(path) {
                let f = file?;
                let path = f.path();
                if let Some(extension) = extension {
                    if let Some(ext) = path.extension() {
                        if ext == extension.as_str() {
                            files.push(path.to_path_buf());
                        }
                    }
                } else {
                    files.push(path.to_path_buf());
                }
            }
        } else {
            if let Some(extension) = extension {
                if let Some(ext) = path.extension() {
                    if ext == extension.as_str() {
                        files.push(path.to_path_buf());
                    }
                }
            } else {
                files.push(path.to_path_buf());
            }
        }
    } else {
        anyhow::bail!("Invalid input path: {}", path.display());
    }

    if files.is_empty() {
        anyhow::bail!("No files found. Check input path?");
    } else {
        cs_eprintln!("[+] Found {} files", files.len());
    }
    Ok(files)
}
