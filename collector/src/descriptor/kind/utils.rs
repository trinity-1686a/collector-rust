use std::collections::HashMap;

use super::DescriptorLine;
use crate::error::{Error, ErrorKind};

pub fn take_uniq<'a>(
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

pub fn take_multi_descriptor_lines<'a>(
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

pub fn take_opt<'a>(
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
