use regex::Regex;
use serde::de::{self, Deserialize, Deserializer};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::path::Path;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub key: String,
    pub acl: Vec<Acl>,
}

#[derive(Deserialize, Debug)]
pub struct Acl {
    pub name: String,
    pub resource: Resource,
}

#[derive(Deserialize, Debug)]
pub struct Resource {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub path: ResourcePath,
    pub accesses: Vec<Accesses>,
}

#[derive(Deserialize, Debug)]
pub struct Accesses {
    pub operation: String,
    pub subject: Option<HashMap<String, SubjectRegex>>,
}

pub fn read_from_file<P: AsRef<Path>>(path: P) -> Result<Config, Box<Error>> {
    let file = File::open(path)?;
    let u = serde_json::from_reader(file)?;
    Ok(u)
}

#[derive(Debug)]
pub enum ResourcePath {
    Str(Vec<String>),
    Regex(Vec<Regex>),
}

impl<'de> Deserialize<'de> for ResourcePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Value::deserialize(deserializer)?;
        if s.is_string() {
            let path: Vec<_> = s
                .as_str()
                .unwrap()
                .split('/')
                .filter(|x| x.len() > 0)
                .map(|x| x.to_string())
                .collect();
            Ok(ResourcePath::Str(path))
        } else if s.is_object() && s["regex"].is_string() {
            let path: Vec<_> = s["regex"]
                .as_str()
                .unwrap()
                .split('/')
                .filter(|&x| x.len() > 0)
                .try_fold(Vec::new(), |mut vec, x| {
                    regex::Regex::new(&format!("^{}$", x)).map(|x| {
                        vec.push(x);
                        vec
                    })
                }).map_err(|x| de::Error::custom(x))?;
            Ok(ResourcePath::Regex(path))
        } else {
            Err(de::Error::custom("illegal resource path"))
        }
    }
}

#[derive(Debug)]
pub struct SubjectRegex(pub Regex);

impl<'de> Deserialize<'de> for SubjectRegex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let regex = Regex::new(&s).map_err(|x| de::Error::custom(x))?;
        Ok(SubjectRegex(regex))
    }
}
