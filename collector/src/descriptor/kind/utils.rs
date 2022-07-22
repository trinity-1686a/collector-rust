use std::collections::HashMap;

use super::DescriptorLine;
use crate::error::{Error, ErrorKind};

pub(crate) fn descriptor_lines(input: &str) -> Result<HashMap<&str, Vec<DescriptorLine>>, Error> {
    use crate::descriptor::nom_combinators::*;

    let mut it = iterator(input, DescriptorLine::parse);
    let desc: HashMap<&str, Vec<DescriptorLine>> = it.fold(HashMap::new(), |mut desc, line| {
        match line.name {
            "reject" | "accept" => desc.entry("accept reject").or_default().push(line),
            _ => desc.entry(line.name).or_default().push(line),
        }
        desc
    });
    let (i, _) = it.finish()?;
    t(eof(i))?;

    Ok(desc)
}

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

pub(crate) fn take_multi_descriptor_lines<'a>(
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
        Err(ErrorKind::MalformedDesc.into())
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

pub(crate) fn hashmap_from_kv_vec(data: Vec<&str>) -> HashMap<String, String> {
    let res: HashMap<String, String> = data.iter().fold(HashMap::new(), |mut res, val| {
        if let Some(t) = val.split_once('=') {
            res.entry(t.0.to_owned()).or_insert_with(|| t.1.to_owned());
            res
        } else {
            res
        }
    });
    res
}
