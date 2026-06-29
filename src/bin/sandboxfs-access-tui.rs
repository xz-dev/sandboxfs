use clap::Parser;

#[derive(Debug, Parser)]
struct Args {
    sandbox: String,
}

fn main() {
    let args = Args::parse();
    match sandboxfs::tui::run(args.sandbox) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("sandboxfs-access-tui: {error}");
            std::process::exit(1);
        }
    }
}
