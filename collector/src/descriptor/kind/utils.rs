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
        $struct {
            $($($field,)*)*
        }
    }};
    (@extractor uniq $rest:ident ($map:expr), ($keyword:expr) [$($name:ident),*] [$($opt:ident),*]) => {
        let mut __item = $map.remove($keyword).ok_or(ErrorKind::MalformedDesc)?;
        if __item.len() != 1 {
            return Err(ErrorKind::MalformedDesc.into());
        }
        let __item = __item.pop().unwrap();
        #[allow(unreachable_patterns)]

        extract_desc!{
            @pattern (&__item.values[..]) $rest [$($name)*] [$($opt)*]
        }
    };
    (@extractor opt $rest:ident ($map:expr), ($keyword:expr) [$($name:ident),*] []) => {
        let __item = $map.remove($keyword);
        let mut __item2 = None;
        let ($rest, $($name),*) = match __item {
            Some(__item) if __item.len() != 1 => {
                return Err(ErrorKind::MalformedDesc.into());
            },
            Some(mut __item) => {
                __item2 = __item.pop();
                #[allow(unreachable_patterns)]
                match &__item2.as_ref().unwrap().values[..] {
                    [$($name,)* rest @ ..] => {
                        if !rest.is_empty() {
                            // TODO add warn here
                        }
                        (Some(rest), $(Some(*$name),)*)
                    },
                    _ => {
                        return Err(ErrorKind::MalformedDesc.into());
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
    (@pattern ($match:expr) $rest:ident [$($name:ident)*] [$($opt:ident)*])=> {
        let expr = $match;
        let ($rest, $($name,)* $($opt,)*) = if let [$($name,)* $($opt,)* rest @ .. ] = expr {
            (rest, $(*$name,)* $(Some($opt),)*)
        } else {
            extract_desc! { @pattern_rec expr [$($name)*] [$($opt)*] []}
        };
    };
    (@pattern_rec $expr:ident [$($name:ident)*]
        [$opt_drop:ident $($opt:ident)*] [$($none:ident)*]) => {
        if let [$($name,)* $($opt,)* ] = $expr {
            (&[][..], $(*$name,)* $(Some($opt),)* $($none,)* None)
        } else {
            extract_desc! { @pattern_rec $expr [$($name)*] [$($opt)*] [$($none)* None]}
        }
    };
    (@pattern_rec $expr:ident [$($name:ident)*] [] [$($none:ident)*])=> {
        if let [$($name,)*] = $expr {
            (&[][..], $(*$name,)* $($none,)*)
        } else {
            return Err(ErrorKind::MalformedDesc.into());
        }
    };
}

pub(crate) use extract_desc;

pub(crate) fn take_uniq<'a>(
    map: &'a mut HashMap<&str, Vec<DescriptorLine>>,
    key: &str,
    len: usize,
) -> Result<Vec<&'a str>, Error> {
    if let Some(mut v) = map.remove(key) {
        if v.len() != 1 {
            return Err(ErrorKind::MalformedDesc.into());
        }
        let v = v.pop().unwrap().values;
        if v.len() < len {
            return Err(ErrorKind::MalformedDesc.into());
        }
        Ok(v)
    } else {
        Err(ErrorKind::MalformedDesc.into())
    }
}

pub(crate) fn take_multi<'a>(
    map: &'a mut HashMap<&str, Vec<DescriptorLine>>,
    key: &str,
    len: usize,
) -> Result<Vec<DescriptorLine<'a>>, Error> {
    if let Some(v) = map.remove(key) {
        let format_ok = v.iter().all(|elem| elem.values.len() >= len);
        if !format_ok {
            return Err(ErrorKind::MalformedDesc.into());
        }
        Ok(v)
    } else {
        Ok(vec![])
    }
}

pub(crate) fn take_opt<'a>(
    map: &'a mut HashMap<&str, Vec<DescriptorLine>>,
    key: &str,
    len: usize,
) -> Result<Option<Vec<&'a str>>, Error> {
    if let Some(mut v) = map.remove(key) {
        if v.len() != 1 {
            return Err(ErrorKind::MalformedDesc.into());
        }
        let v = v.pop().unwrap().values;
        if v.len() < len {
            return Err(ErrorKind::MalformedDesc.into());
        }
        Ok(Some(v))
    } else {
        Ok(None)
    }
}
