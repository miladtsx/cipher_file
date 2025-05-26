use clap::{ArgGroup, Parser};
use std::io;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(group(
    ArgGroup::new("mode")
        .required(true)
        .args(["encrypt", "decrypt"]),
))]
struct Args {
    /// The path to read the input file
    #[arg(short, long)]
    input: String,

    /// The path to store the output file
    #[arg(short, long)]
    output: String,

    /// the password to encrypt/decrypt
    #[arg(short, long)]
    password: String,

    /// Encryptp plain text
    #[arg(short = 'e', long = "encrypt")]
    encrypt: bool,

    /// Decrypt an encrypted file
    #[arg(short = 'd', long = "decrypt")]
    decrypt: bool,
}

fn main() -> io::Result<()> {
    sodiumoxide::init().expect("Failed to initialize sodiumoxide");
    let args = Args::parse();

    if args.encrypt {
        file_encryptor::encrypt_file(&args.input, &args.output, &args.password)?;
    } else if args.decrypt {
        file_encryptor::decrypt_file(&args.input, &args.output, &args.password)?;
    }

    Ok(())
}
