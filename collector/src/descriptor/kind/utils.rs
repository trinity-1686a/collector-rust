use std::collections::HashMap;

use super::DescriptorLine;
use crate::error::{Error, ErrorKind};

pub(crate) fn descriptor_lines(input: &str) -> Result<HashMap<&str, Vec<DescriptorLine>>, Error> {
    use crate::descriptor::nom_combinators::*;

    let mut it = iterator(input, DescriptorLine::parse);
    let desc: (HashMap<&str, Vec<DescriptorLine>>, u32) =
        it.fold((HashMap::new(), 1), |(mut desc, i), mut line| {
            line.line = i;
            desc.entry(line.name).or_default().push(line);
            (desc, i + 1)
        });
    let (i, _) = it.finish()?;
    t(eof(i))?;

    Ok(desc.0)
}

macro_rules! extract_desc {
    ( $map:expr =>
        $struct:ident $rest:ident {
            $(
                $extractor:ident($($keyword:expr),*) [$($name:ident),* $(, @ $($optional:ident),*)?] => {
                    $(
                        $field:ident: $convert:expr,
                    )*
                },
            )*
        }
    ) => {{
        #![allow(unused_variables)]
        $(
            let ($($field,)*) = {
                extract_desc! {
                    @extractor $extractor $rest ($map), ($($keyword),*) [$($name),*] [$($($optional),*)?]
                }
                ($(
                    $convert,
                )*)
            };
        )*
        {
            /* TODO add logging
            if !$map.is_empty() {
                let mut stdout = std::io::stdout().lock();
                use std::io::Write;
                let _ = writeln!(stdout, "map isn't empty: {}", $map.len());
                for (k,v) in $map.iter() {
                    let _ = writeln!(stdout, "unused key: '{k}' = {v:?}");
                }
            }
            */
        }
        $struct {
            $($($field,)*)*
        }
    }};
    (@extractor uniq $rest:ident ($map:expr), ($keyword:expr) [$($name:ident),*] [$($opt:ident),*]) => {
        let mut __item = $map.remove($keyword).ok_or(ErrorKind::MalformedDesc(
                       concat!("line ", $keyword, " missing").to_owned()
                ))?;
        if __item.len() != 1 {
            return Err(ErrorKind::MalformedDesc(
                       concat!("line ", $keyword, " appeared multiple times").to_owned()
                    ).into());
        }
        let __item = __item.pop().unwrap();

        extract_desc!{
            @pattern (&__item.values[..]) $rest [$($name)*] [$($opt)*] ($keyword)
        }
    };
    (@extractor opt $rest:ident ($map:expr), ($keyword:expr) [$($name:ident),*] []) => {
        let __item = $map.remove($keyword);
        let mut __item2 = None;
        let ($rest, $($name),*) = match __item {
            Some(__item) if __item.len() != 1 => {
                return Err(ErrorKind::MalformedDesc(
                       concat!("line ", $keyword, " appeared multiple times").to_owned()
                   ).into());
            },
            Some(mut __item) => {
                __item2 = __item.pop();
                #[allow(unreachable_patterns)]
                match &__item2.as_ref().unwrap().values[..] {
                    [$($name,)* rest @ ..] => {
                        (Some(rest), $(Some(*$name),)*)
                    },
                    _ => {
                        return Err(ErrorKind::MalformedDesc(
                                concat!("missing parameters to ", $keyword).to_owned()
                            ).into());
                    },
                }
            },
            None => std::default::Default::default(),
        };
    };
    (@extractor multi $rest:ident ($map:expr), ($($keyword:expr),*) [] []) => {
        let mut $rest = vec![];
        $(
            if let Some(mut vec) = $map.remove($keyword) {
                $rest.append(&mut vec);
            }
        )*
        $rest.sort_by_key(|e| e.line);
        let $rest = $rest;
    };
    (@pattern ($match:expr) $rest:ident [$($name:ident)*] [$($opt:ident)*] ($keyword:expr))=> {
        let expr = $match;

        #[allow(irrefutable_let_patterns)]
        let ($rest, $($name,)* $($opt,)*) = if let [$($name,)* $($opt,)* rest @ .. ] = expr {
            (rest, $(*$name,)* $(Some($opt),)*)
        } else {
            extract_desc! { @pattern_rec expr [$($name)*] [$($opt)*] [] ($keyword)}
        };
    };
    (@pattern_rec $expr:ident [$($name:ident)*]
        [$opt_drop:ident $($opt:ident)*] [$($none:ident)*] ($keyword:expr)) => {
        if let [$($name,)* $($opt,)* ] = $expr {
            (&[][..], $(*$name,)* $(Some($opt),)* $($none,)* None)
        } else {
            extract_desc! { @pattern_rec $expr [$($name)*] [$($opt)*] [$($none)* None] ($keyword)}
        }
    };
    (@pattern_rec $expr:ident [$($name:ident)*] [] [$($none:ident)*] ($keyword:expr))=> {
        if let [$($name,)*] = $expr {
            (&[][..], $(*$name,)* $($none,)*)
        } else {
            return Err(ErrorKind::MalformedDesc(
                        concat!("missing parameters to ", $keyword).to_owned()
                    ).into());
        }
    };
}

pub(crate) fn hashmap_from_kv_vec(data: Vec<&str>) -> Result<HashMap<String, String>, Error> {
    data.iter()
        .map(|val| {
            let (a, b) = val
                .split_once('=')
                .ok_or_else(|| ErrorKind::MalformedDesc("Key value malformed".to_owned()))?;
            Ok((a.to_owned(), b.to_owned()))
        })
        .collect()
}

pub(crate) use extract_desc;
