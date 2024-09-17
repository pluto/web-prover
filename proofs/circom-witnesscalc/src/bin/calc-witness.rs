use std::env;
use std::fs::File;
use std::io::Write;
use std::time::Instant;
use circom_witnesscalc::{calc_witness, wtns_from_witness};

struct Args {
    graph_file: String,
    inputs_file: String,
    witness_file: String,
}

fn parse_args() -> Args {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <graph.bin> <inputs.json> <witness.wtns>", args[0]);
        std::process::exit(1);
    }

    Args {
        graph_file: args[1].clone(),
        inputs_file: args[2].clone(),
        witness_file: args[3].clone(),
    }
}

fn main() {
    let args = parse_args();

    let inputs_data = std::fs::read_to_string(&args.inputs_file)
        .expect("Failed to read input file");

    let graph_data = std::fs::read(&args.graph_file).expect("Failed to read graph file");

    let start = Instant::now();

    let witness = calc_witness(&inputs_data, &graph_data).unwrap();
    let wtns_bytes = wtns_from_witness(witness);

    let duration = start.elapsed();
    println!("Witness generated in: {:?}", duration);

    {
        let mut f = File::create(&args.witness_file).unwrap();
        f.write_all(&wtns_bytes).unwrap();
    }

    println!("witness saved to {}", &args.witness_file);
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ok() {
        println!("OK");
    }

}