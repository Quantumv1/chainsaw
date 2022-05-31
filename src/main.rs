#[macro_use]
extern crate chainsaw;

use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;
use chrono::NaiveDateTime;
use regex::Regex;
use structopt::StructOpt;
use walkdir::WalkDir;

use chainsaw::{
    cli, get_files, lint_rule, load_rule, set_writer, Format, Hunter, RuleKind, Searcher, Writer,
};

#[derive(StructOpt)]
#[structopt(
    name = "chainsaw",
    about = "Rapidly Search and Hunt through windows event logs"
)]
struct Opts {
    /// Hide Chainsaw's banner
    #[structopt(long)]
    no_banner: bool,
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(StructOpt)]
enum Command {
    /// Hunt through event logs using detection rules and builtin logic
    Hunt {
        rules: PathBuf,

        path: Vec<PathBuf>,

        #[structopt(short = "m", long = "mapping", number_of_values = 1)]
        mapping: Option<Vec<PathBuf>>,
        #[structopt(short = "r", long = "rule", number_of_values = 1)]
        rule: Option<Vec<PathBuf>>,

        #[structopt(long = "column-width")]
        column_width: Option<u32>,
        #[structopt(long = "extension")]
        extension: Option<String>,
        #[structopt(long = "from")]
        from: Option<NaiveDateTime>,
        #[structopt(long = "full")]
        full: bool,
        #[structopt(group = "format", long = "json")]
        json: bool,
        #[structopt(short = "o", long = "output")]
        output: Option<PathBuf>,
        #[structopt(short = "q")]
        quiet: bool,
        #[structopt(long = "skip-errors")]
        skip_errors: bool,
        #[structopt(long = "to")]
        to: Option<NaiveDateTime>,
    },

    /// Lint provided rules to ensure that they load correctly
    Lint {
        path: PathBuf,
        #[structopt(long = "kind", default_value = "chainsaw")]
        kind: RuleKind,
    },

    /// Search through event logs for specific event IDs and/or keywords
    Search {
        #[structopt(required_unless = "regexp")]
        pattern: Option<String>,

        path: Vec<PathBuf>,

        #[structopt(short = "e", long = "regexp", number_of_values = 1)]
        regexp: Option<Regex>,

        // TODO: Remove this as its not generic
        #[structopt(long = "event")]
        event_id: Option<u32>,
        #[structopt(long = "extension")]
        extension: Option<String>,
        #[structopt(long = "from")]
        from: Option<NaiveDateTime>,
        #[structopt(short = "i", long = "ignore-case")]
        ignore_case: bool,
        #[structopt(long = "json")]
        json: bool,
        #[structopt(short = "o", long = "output")]
        output: Option<PathBuf>,
        #[structopt(short = "q")]
        quiet: bool,
        #[structopt(long = "skip-errors")]
        skip_errors: bool,
        #[structopt(long = "to")]
        to: Option<NaiveDateTime>,
    },
}

fn print_title() {
    cs_eprintln!(
        "
 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By F-Secure Countercept (@FranticTyping, @AlexKornitzer)
"
    );
}

fn init_writer(output: Option<PathBuf>, json: bool, quiet: bool) -> crate::Result<()> {
    let output = match &output {
        Some(path) => {
            let file = match File::create(path) {
                Ok(f) => f,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Unable to write to specified output file - {} - {}",
                        path.display(),
                        e
                    ));
                }
            };
            Some(file)
        }
        None => None,
    };
    let format = if json { Format::Json } else { Format::Std };
    let writer = Writer {
        format,
        output,
        quiet,
    };
    set_writer(writer).expect("could not set writer");
    Ok(())
}

fn main() -> Result<()> {
    let opts = Opts::from_args();
    match opts.cmd {
        Command::Hunt {
            rules,
            path,

            mapping,
            rule,

            column_width,
            extension,
            from,
            full,
            json,
            output,
            quiet,
            skip_errors,
            to,
        } => {
            init_writer(output, json, quiet)?;
            if !opts.no_banner {
                print_title();
            }
            let mut rules = vec![rules];
            if let Some(rule) = rule {
                rules.extend(rule)
            };
            cs_eprintln!("[+] Loading rules...");
            let mut failed = 0;
            let mut rs = vec![];
            for path in rules {
                for file in WalkDir::new(path) {
                    let f = file?;
                    let path = f.path();
                    // TODO: Remove..
                    match load_rule(&RuleKind::Sigma, path) {
                        Ok(mut r) => rs.append(&mut r),
                        Err(_) => {
                            failed += 1;
                        }
                    }
                }
            }
            let rules = rs;
            if failed > 0 {
                cs_eprintln!(
                    "[+] Loaded {} detection rules ({} were not loaded)",
                    rules.len(),
                    failed
                );
            } else {
                cs_eprintln!("[+] Loaded {} detection rules", rules.len());
            }
            let mut hunter = Hunter::builder()
                .rules(rules)
                .mappings(mapping.unwrap_or_default())
                .skip_errors(skip_errors);
            if let Some(from) = from {
                hunter = hunter.from(from);
            }
            if let Some(to) = to {
                hunter = hunter.to(to);
            }
            let hunter = hunter.build()?;
            let mut files = vec![];
            for path in &path {
                files.extend(get_files(path, &extension)?);
            }
            let mut detections = vec![];
            let pb = cli::init_progress_bar(files.len() as u64, "Hunting".to_string());
            for file in &files {
                pb.tick();
                detections.extend(hunter.hunt(file)?);
                pb.inc(1);
            }
            pb.finish();
            detections.sort_by(|x, y| x.timestamp.cmp(&y.timestamp));
            if json {
                cli::print_json(&detections, hunter.rules())?;
            } else {
                cli::print_detections(
                    &detections,
                    hunter.mappings(),
                    hunter.rules(),
                    column_width.unwrap_or(40),
                    full,
                );
            }
            cs_eprintln!(
                "[+] {} Detections found on {} documents",
                detections.iter().map(|d| d.hits.len()).sum::<usize>(),
                detections.len()
            );
        }
        Command::Lint { path, kind } => {
            init_writer(None, false, false)?;
            if !opts.no_banner {
                print_title();
            }
            cs_eprintln!("[+] Validating supplied detection rules...");
            let mut count = 0;
            let mut failed = 0;
            for file in WalkDir::new(path) {
                let f = file?;
                let path = f.path();
                if path.is_file() {
                    if let Err(e) = lint_rule(&kind, path) {
                        failed += 1;
                        cs_eprintln!("[!] {}", e);
                        continue;
                    }
                    count += 1;
                }
            }
            cs_eprintln!(
                "[+] Validated {} detection rules ({} were not loaded)",
                count,
                failed
            );
        }
        Command::Search {
            path,

            pattern,
            regexp,

            event_id,
            extension,
            from,
            ignore_case,
            json,
            output,
            quiet,
            skip_errors,
            to,
        } => {
            init_writer(output, json, quiet)?;
            if !opts.no_banner {
                print_title();
            }
            let mut paths = if regexp.is_some() {
                let mut scratch = pattern
                    .as_ref()
                    .map(|p| vec![PathBuf::from(p)])
                    .unwrap_or_default();
                scratch.extend(path);
                scratch
            } else {
                path
            };
            if paths.is_empty() {
                paths.push(
                    std::env::current_dir().expect("could not get current working directory"),
                );
            }
            let mut files = vec![];
            for path in &paths {
                files.extend(get_files(path, &extension)?);
            }
            let mut searcher = Searcher::builder()
                .ignore_case(ignore_case)
                .skip_errors(skip_errors);
            if let Some(event_id) = event_id {
                searcher = searcher.event_id(event_id);
            }
            if let Some(pattern) = pattern {
                searcher = searcher.pattern(pattern);
            }
            if let Some(regexp) = regexp {
                searcher = searcher.regex(regexp);
            }
            if let Some(from) = from {
                searcher = searcher.from(from);
            }
            if let Some(to) = to {
                searcher = searcher.to(to);
            }
            let searcher = searcher.build()?;
            cs_eprintln!("[+] Searching event logs...");
            if json {
                cs_print!("[");
            }
            let mut hits = 0;
            for file in &files {
                for res in searcher.search(file)?.iter() {
                    let hit = match res {
                        Ok(hit) => hit,
                        Err(e) => {
                            if skip_errors {
                                continue;
                            }
                            anyhow::bail!("Failed to search file... - {}", e);
                        }
                    };
                    if json {
                        if !(hits == 0) {
                            cs_print!(",");
                        }
                        cs_print_json!(&hit)?;
                    } else {
                        cs_print_yaml!(&hit)?;
                    }
                    hits += 1;
                }
            }
            if json {
                cs_println!("]");
            }
            cs_println!("[+] Found {} matching log entries", hits);
        }
    }
    Ok(())
}
