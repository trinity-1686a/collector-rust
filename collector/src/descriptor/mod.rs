pub mod file_reader;
pub mod kind;

pub use kind::{Descriptor, Type, VersionnedType};

pub(crate) mod nom_combinators {
    use std::collections::HashMap;

    use chrono::{DateTime, TimeZone, Utc};

    pub use nom::bytes::complete::{tag, take, take_till};
    pub use nom::character::complete::{
        anychar, char, hex_digit1, line_ending, space0, space1, u32,
    };
    pub use nom::combinator::{eof, iterator, map, map_parser, map_res, peek};
    pub use nom::multi::fold_many_m_n;
    pub use nom::sequence::tuple;

    /// Force type to help rustc find what we want
    pub fn t<T>(r: Result<T, nom::Err<()>>) -> Result<T, nom::Err<()>> {
        r
    }

    pub fn fingerprint(input: &str) -> nom::IResult<&str, &str, nom::error::Error<&str>> {
        map_parser(hex_digit1, take(40usize))(input)
    }

    pub fn date(input: &str) -> nom::IResult<&str, DateTime<Utc>, nom::error::Error<&str>> {
        let format = "%Y-%m-%d %H:%M:%S";
        map_res(take("yyyy-mm-dd hh:mm:ss".len()), |s| {
            Utc.datetime_from_str(s, format)
        })(input)
    }

    pub fn kv_space(
        input: &str,
    ) -> nom::IResult<&str, HashMap<String, String>, nom::error::Error<&str>> {
        let mut it = iterator(
            input,
            tuple((
                char(' '),
                take_till(|c| c == '='),
                char('='),
                take_till(|c| c == ' ' || c == '\n'),
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
}
