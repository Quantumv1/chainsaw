use std::fs;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

pub mod evtx;

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
