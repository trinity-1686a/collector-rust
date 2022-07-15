pub mod file_reader;
pub mod kind;

pub use kind::{Descriptor, Type, VersionnedType};

pub(crate) mod nom_combinators {
    use std::collections::HashMap;

    use chrono::{DateTime, TimeZone, Utc};

    pub use nom::Parser;
    pub use nom::bytes::complete::{tag, take, take_till, take_until};
    pub use nom::character::complete::{
        anychar, char, hex_digit1, line_ending, space0, space1, u32,
    };
    pub use nom::combinator::{eof, iterator, map, map_parser, map_res, opt, peek};
    pub use nom::multi::fold_many_m_n;
    pub use nom::sequence::tuple;

    /// Force type to help rustc find what we want
    pub fn t<T>(r: Result<T, nom::Err<()>>) -> Result<T, nom::Err<()>> {
        r
    }

    /// Parse a single word, terminated by a space or a newline.
    pub fn word(input: &str) -> nom::IResult<&str, &str, nom::error::Error<&str>> {
        take_till(|c| c == ' ' || c == '\n')(input)
    }

    /// Parse a 160 bit hexadecimal bloc, which correspond to Tor relay fingerprint.
    pub fn fingerprint(input: &str) -> nom::IResult<&str, &str, nom::error::Error<&str>> {
        map_parser(hex_digit1, take(40usize))(input)
    }

    /// Parse a date
    pub fn date(input: &str) -> nom::IResult<&str, DateTime<Utc>, nom::error::Error<&str>> {
        let format = "%Y-%m-%d %H:%M:%S";
        map_res(take("yyyy-mm-dd hh:mm:ss".len()), |s| {
            Utc.datetime_from_str(s, format)
        })(input)
    }

    /// Parse a set of key=value separated by spaces, until end of line
    pub fn kv_space(
        input: &str,
    ) -> nom::IResult<&str, HashMap<String, String>, nom::error::Error<&str>> {
        let mut it = iterator(
            input,
            tuple((
                char(' '),
                take_till(|c| c == '='),
                char('='),
                word,
                peek(anychar),
            )),
        );

        let mut kv = HashMap::new();
        for (_, k, _, v, eol) in &mut it {
            kv.insert(k.to_owned(), v.to_owned());
            if eol == '\n' {
                break;
            }
        }

        let (i, _) = it.finish()?;
        Ok((i, kv))
    }

    /// Parse a single line into a first element, and a list of other elements, space delimited.
    pub fn sp_separated(
        input: &str,
    ) -> nom::IResult<&str, (&str, Vec<&str>), nom::error::Error<&str>> {
        let (i, key) = word(input)?;
        let mut it = iterator(i, tuple((char(' '), word, peek(anychar))));

        let mut res = Vec::new();
        for (_, word, eol) in &mut it {
            res.push(word);
            if eol == '\n' {
                break;
            }
        }
        let (i, _) = it.finish()?;
        Ok((i, (key, res)))
    }

    /// Parse what looks like a PEM content. Accept a broad range of inputs that are
    /// technically not valid, like PEM with a non base64 content or an illegal label.
    pub fn cert(
        input: &str,
    ) -> nom::IResult<&str, &str, nom::error::Error<&str>> {
        let start_len = input.len();

        let (i, _) = tag("-----BEGIN ")(input)?;
        let (i, _label) = take_until("--")(i)?;
        let (i, _) = tag("-----\n")(i)?;
        let (i, _b64) = take_until("--")(i)?;
        let (i, _) = tag("-----END ")(i)?;
        let (i, _label) = take_until("--")(i)?;
        let (i, _) = tag("-----\n")(i)?;

        let len = start_len - i.len();

        Ok((i, &input[..len]))
    }
}
