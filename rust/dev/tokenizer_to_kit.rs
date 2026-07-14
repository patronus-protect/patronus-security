use kitoken::Kitoken;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("usage: tokenizer_to_kit <tokenizer.json> <tokenizer.kit>".into());
    }
    Kitoken::from_tokenizers_file(&args[1])?.to_file(&args[2])?;
    Ok(())
}
