use anyhow::{bail, Result};

use std::path::Path;

pub(crate) fn extract_section<T: AsRef<Path>>(file: T, section: &str) -> Result<String> {
    let file = std::fs::read(file)?;
    let file = std::str::from_utf8(&file)?;

    let section = format!("\n{section} ");
    if let Some(pos) = file.find(&section) {
        let section_content = &file[pos + 1..];

        if let Some(pos) = section_content
            .char_indices()
            .zip(section_content.chars().skip(1))
            .find(|((_pos, c1), c2)| *c1 == '\n' && !" \n".contains(*c2))
            .map(|((pos, _), _)| pos)
        {
            let section_content = section_content[..pos].to_owned();
            return Ok(section_content);
        }
    }

    bail!("failed to extract section from file");
}

struct ParseSpec {
    header: Vec<Rule>,
}

struct Rule {
    position: Position,
    quantity: Quantity,
    extra_args: bool,
    optional_before: Option<Version>,
}

enum Position {
    Start,
    End,
    Any,
}

enum Quantity {
    ExactlyOnce,
    AtMostOnce,
    AnyNumber,
    OnceOrMore,
}

struct Version(u32, u32, u32, u32);

impl ParseSpec {
    fn from_section_text(section: &str) -> Result<Self> {
        todo!()
    }
}
