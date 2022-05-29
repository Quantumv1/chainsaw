#[macro_use]
extern crate chainsaw;

use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;
use chrono::NaiveDateTime;
use regex::Regex;
use structopt::StructOpt;
use walkdir::WalkDir;

// TODO: Remove
use ::evtx::{EvtxParser, ParserSettings};

use chainsaw::{cli, evtx, lint_rule, load_rule, set_writer, Format, Hunter, RuleKind, Writer};

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
        #[structopt(group = "format", long = "csv")]
        csv: bool,
        #[structopt(long = "from")]
        from: Option<NaiveDateTime>,
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

        // TODO: Remove this
        #[structopt(long = "event")]
        event_id: Option<u32>,
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

fn init_writer(output: Option<PathBuf>, csv: bool, json: bool, quiet: bool) -> crate::Result<()> {
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
    let format = if csv {
        Format::Csv
    } else if json {
        Format::Json
    } else {
        Format::Std
    };
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
            csv,
            from,
            json,
            output,
            quiet,
            skip_errors,
            to,
        } => {
            init_writer(output, csv, json, quiet)?;
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
            // TODO: Abstract away from evtx...
            let mut files = vec![];
            for path in &path {
                files.extend(evtx::get_files(path)?);
            }
            let mut detections = vec![];
            let pb = cli::init_progress_bar(files.len() as u64, "Hunting".to_string());
            for file in &files {
                pb.tick();
                detections.extend(hunter.hunt(file)?);
                pb.inc(1);
            }
            pb.finish();
            if csv {
            } else if json {
            } else {
                cli::print_detections(&detections, column_width.unwrap_or(40));
            }
            cs_println!("[+] {} Detections found", detections.len());
        }
        Command::Lint { path, kind } => {
            init_writer(None, false, false, false)?;
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
            from,
            ignore_case,
            json,
            output,
            quiet,
            skip_errors,
            to,
        } => {
            init_writer(output, false, json, quiet)?;
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
            // TODO: Abstract away from evtx...
            let mut files = vec![];
            for path in &paths {
                files.extend(evtx::get_files(path)?);
            }
            let mut hits = 0;
            cs_eprintln!("[+] Searching event logs...");
            if json {
                cs_print!("[");
            }
            for evtx in &files {
                let kind = infer::get_from_path(evtx);
                println!("{:?}", kind);
                std::process::exit(1);
                // Parse EVTx files
                let settings = ParserSettings::default()
                    .separate_json_attributes(true)
                    .num_threads(0);
                let parser = match EvtxParser::from_path(evtx) {
                    Ok(a) => a.with_configuration(settings),
                    Err(e) => {
                        if skip_errors {
                            continue;
                        }
                        anyhow::bail!("{:?} - {}", evtx, e);
                    }
                };

                // Search EVTX files for user supplied arguments
                hits += evtx::search(
                    parser,
                    &pattern,
                    &regexp,
                    hits == 0,
                    from,
                    to,
                    event_id,
                    ignore_case,
                    json,
                )?;
            }
            if json {
                cs_println!("]");
            }
            cs_println!("[+] Found {} matching log entries", hits);
        }
    }
    Ok(())
}
