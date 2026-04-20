use clap::{Parser, Subcommand};
use nu_table::{NuTable, TableTheme};
use std::process::Command;
use std::time::Instant;

/// Nexus-IO Benchmark Tool
#[derive(Parser)]
#[command(name = "benchmark")]
#[command(about = "A standalone tool for benchmarking JS runtimes", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Benchmark specific runtimes
    Runtimes {
        /// Runtime commands to benchmark (e.g., "node", "deno run", "./nexus-io js")
        #[arg(required = true, num_args = 1..)]
        runtimes: Vec<String>,
        
        /// Number of runs per runtime
        #[arg(short, long, default_value_t = 3)]
        runs: usize,
    },
}

const BENCHMARK_SCRIPT: &str = include_str!("../../benchmark.js");

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Runtimes { runtimes, runs } => {
            println!("Starting benchmark suite...");
            println!("Script: Fibonacci(35)");
            println!("Runs per engine: {}\n", runs);

            // Write temporary benchmark file
            let bench_file = "temp_benchmark.js";
            std::fs::write(bench_file, BENCHMARK_SCRIPT).expect("Failed to write benchmark script");

            let mut results = Vec::new();

            for runtime_cmd in runtimes {
                print!("Benchmarking '{}'... ", runtime_cmd);
                use std::io::Write;
                std::io::stdout().flush().unwrap();

                let mut total_duration = std::time::Duration::new(0, 0);
                let mut success = true;

                // Parse the runtime command string
                let parts: Vec<&str> = runtime_cmd.split_whitespace().collect();
                if parts.is_empty() {
                    eprintln!("Invalid empty command");
                    continue;
                }
                let exe = parts[0];
                let args = &parts[1..];

                for i in 1..=runs {
                    let start = Instant::now();
                    
                    let mut cmd = Command::new(exe);
                    cmd.args(args);
                    cmd.arg(bench_file);

                    let output = cmd.output();
                    
                    match output {
                        Ok(out) => {
                            if !out.status.success() {
                                println!("FAILED (Run {})", i);
                                eprintln!("{}", String::from_utf8_lossy(&out.stderr));
                                success = false;
                                break;
                            }
                            total_duration += start.elapsed();
                        }
                        Err(e) => {
                            println!("ERROR");
                            eprintln!("Failed to execute '{}': {}", runtime_cmd, e);
                            success = false;
                            break;
                        }
                    }
                }

                if success {
                    let avg = total_duration / runs as u32;
                    println!("Done ({:?})", avg);
                    results.push((runtime_cmd, format!("{:?}", avg)));
                } else {
                    results.push((runtime_cmd, "FAILED".to_string()));
                }
            }

            // Cleanup
            let _ = std::fs::remove_file(bench_file);

            println!("\nBenchmark Results:");
            print_nu_table(results);
        }
    }
}

fn print_nu_table(data: Vec<(String, String)>) {
    let rows = data.len() + 1; // +1 for header
    let cols = 2; // Runtime, Average Time
    
    let mut table = NuTable::new(rows, cols);
    
    // Set Theme
    table.set_theme(TableTheme::rounded());
    
    // Set Header
    table.insert((0, 0), "Runtime".to_string());
    table.insert((0, 1), "Average Time".to_string());
    
    // Set Header Style (Optional, mimicking Nushell default which is bold green)
    // We would need nu_color_config::TextStyle, but for now let's rely on default structure
    // Validating if we can just set data.
    
    // Set Data
    for (i, (runtime, time)) in data.iter().enumerate() {
        let row_idx = i + 1;
        table.insert((row_idx, 0), runtime.clone());
        table.insert((row_idx, 1), time.clone());
    }

    // Configure structure to indicate header presence
    // set_structure(index, header, footer)
    table.set_structure(false, true, false); 

    // Draw
    // termwidth 80 as a safe default
    let output = table.draw(80);
    
    if let Some(s) = output {
        println!("{}", s);
    } else {
        println!("Error rendering table");
    }
}
