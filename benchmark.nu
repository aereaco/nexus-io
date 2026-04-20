# Nexus vs Deno vs Node Performance Benchmark

def main [] {
    let script = "benchmark.js"
    let runs = 3

    print $"Starting performance benchmark with ($script)..."
    print $"Number of runs per engine: ($runs)"
    print ""

    let engines = [
        { name: "Node.js", cmd: "node", args: [$script] },
        { name: "Deno", cmd: "deno", args: ["run", $script] },
        { name: "Nexus-IO", cmd: "./target/release/nexus-io", args: ["js", $script] }
    ]

    let results = $engines | each { |engine|
        print $"Benchmarking ($engine.name)..."
        let timings = 1..$runs | each { |i|
            let start = (date now)
            run-external $engine.cmd ...$engine.args
            let end = (date now)
            ($end - $start)
        }
        let avg = ($timings | math sum) / $runs
        { engine: $engine.name, average_time: $avg }
    }

    print ""
    print "Benchmark Results:"
    $results | table
}
