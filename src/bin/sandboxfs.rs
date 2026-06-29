fn main() {
    match sandboxfs::cli::main_entry() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("sandboxfs: {error}");
            std::process::exit(1);
        }
    }
}
