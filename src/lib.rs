extern crate jsonwebtoken;
#[macro_use]
extern crate serde_derive;
extern crate regex;
extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate log;
extern crate chrono;
extern crate simplelog;
#[macro_use]
extern crate lazy_static;
extern crate percent_encoding;

mod config;
mod misc;
use chrono::prelude::*;
use jsonwebtoken::{decode, Algorithm, Validation};
use regex::Regex;
use serde_json::Value;
use simplelog::{CombinedLogger, Config, LevelFilter, SharedLogger, TermLogger, WriteLogger};
use std::collections::HashMap;
use std::ffi::CStr;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::os::raw::{c_char, c_int, c_long, c_uint, c_void};
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Mutex, RwLock};
use std::thread;
use std::time::SystemTime;
use percent_encoding::percent_decode;

pub const DEFAULT_CONFIG_PATH_OPT_KEY: &str = "chipin_config_path";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/mosquitto/acl.json";
pub const DEFAULT_AUTH_LOG_FILE_NAME_OPT_KEY: &str = "chipin_auth_log_file_name";
pub const DEFAULT_AUTH_LOG_FILE_NAME: &str = "/var/log/mosquitto/auth.log";
pub const DEFAULT_LOG_FILE_NAME_OPT_KEY: &str = "chipin_log_file";
pub const DEFAULT_LOG_FILE_NAME: &str = "/var/log/mosquitto/chipin-plugin.log";
pub const DEFAULT_LOG_LEVEL_OPT_KEY: &str = "chipin_log_level";
pub const CONFIG_FILE_CHECK_INTERVAL: u64 = 1;
pub const LOG_DATE_FORMAT: &str = "%Y-%m-%d %H:%M:%S";
pub const PATH_TRANSACTION: &str = r"^/m/d/([^/]+)/transaction$";
pub const PATH_SUBSET_TRANSACTION: &str = r"^/m/d/([^/]+)/subset/([^/]+)/transaction$";

pub const NULL: *const c_char = 0 as *const c_char;

pub const MOSQ_ACL_NONE: c_int = 0x00;
pub const MOSQ_ACL_READ: c_int = 0x01;
pub const MOSQ_ACL_WRITE: c_int = 0x02;
pub const MOSQ_ACL_SUBSCRIBE: c_int = 0x04;

pub const MOSQ_ERR_CONN_PENDING: c_int = -1;
pub const MOSQ_ERR_SUCCESS: c_int = 0;
pub const MOSQ_ERR_NOMEM: c_int = 1;
pub const MOSQ_ERR_PROTOCOL: c_int = 2;
pub const MOSQ_ERR_INVAL: c_int = 3;
pub const MOSQ_ERR_NO_CONN: c_int = 4;
pub const MOSQ_ERR_CONN_REFUSED: c_int = 5;
pub const MOSQ_ERR_NOT_FOUND: c_int = 6;
pub const MOSQ_ERR_CONN_LOST: c_int = 7;
pub const MOSQ_ERR_TLS: c_int = 8;
pub const MOSQ_ERR_PAYLOAD_SIZE: c_int = 9;
pub const MOSQ_ERR_NOT_SUPPORTED: c_int = 10;
pub const MOSQ_ERR_AUTH: c_int = 11;
pub const MOSQ_ERR_ACL_DENIED: c_int = 12;
pub const MOSQ_ERR_UNKNOWN: c_int = 13;
pub const MOSQ_ERR_ERRNO: c_int = 14;
pub const MOSQ_ERR_EAI: c_int = 15;
pub const MOSQ_ERR_PROXY: c_int = 16;

lazy_static! {
    static ref REGEX_PATH_TRANSACTION: Regex = Regex::new(PATH_TRANSACTION).unwrap();
    static ref REGEX_PATH_SUBSET_TRANSACTION: Regex = Regex::new(PATH_SUBSET_TRANSACTION).unwrap();
}

pub struct UserData {
    config_path: String,
    config_info: RwLock<ConfigInfo>,
    client_map: RwLock<HashMap<*const mosquitto, String>>,
    log: Mutex<Option<Sender<(DateTime<Local>, String)>>>,
    log_thread: thread::JoinHandle<()>,
}

pub struct ConfigInfo {
    last_check_time: SystemTime,
    file_time: i64,
    config: Option<Box<config::Config>>,
}

#[repr(C)]
pub struct mosquitto {}

#[repr(C)]
pub struct mosquitto_opt {
    pub key: *const c_char,
    pub value: *const c_char,
}

#[repr(C)]
pub struct mosquitto_auth_opt {
    pub key: *const c_char,
    pub value: *const c_char,
}

#[repr(C)]
pub struct mosquitto_acl_msg {
    pub topic: *const c_char,
    pub payload: *const c_void,
    pub payloadlen: c_long,
    pub qos: c_int,
    pub retain: c_uint,
}

#[no_mangle]
pub extern "C" fn proc_mosquitto_auth_plugin_init(
    user_data: *mut *mut UserData,
    opts: *const mosquitto_opt,
    opt_count: c_int,
) -> c_int {
    // load a mosquitto config
    let mut opt_map: HashMap<String, String> = HashMap::new();
    for n in 0..opt_count {
        let opt_key = unsafe { CStr::from_ptr((*opts.offset(n as isize)).key) }.to_string_lossy();
        let opt_value =
            unsafe { CStr::from_ptr((*opts.offset(n as isize)).value) }.to_string_lossy();
        opt_map.insert(opt_key.into_owned(), opt_value.into_owned());
    }
    let config_path = match opt_map.get(DEFAULT_CONFIG_PATH_OPT_KEY) {
        Some(x) => &x,
        None => DEFAULT_CONFIG_PATH,
    };
    let auth_log_file_name = match opt_map.get(DEFAULT_AUTH_LOG_FILE_NAME_OPT_KEY) {
        Some(x) => x.to_string(),
        None => DEFAULT_AUTH_LOG_FILE_NAME.to_string(),
    };
    let log_file_name = match opt_map.get(DEFAULT_LOG_FILE_NAME_OPT_KEY) {
        Some(x) => &x,
        None => DEFAULT_LOG_FILE_NAME,
    };
    let log_level: &str = match opt_map.get(DEFAULT_LOG_LEVEL_OPT_KEY) {
        Some(x) => &x,
        None => "Info",
    };

    // init loggers
    let mut log_list: Vec<Box<SharedLogger>> = vec![];
    TermLogger::new(LevelFilter::Debug, Config::default()).map(|x| log_list.push(x));
    if let Ok(log_file) = OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_file_name)
    {
        log_list.push(WriteLogger::new(
            LevelFilter::from_str(log_level).unwrap_or(LevelFilter::Info),
            Config::default(),
            log_file,
        ));
    }
    CombinedLogger::init(log_list).unwrap();

    info!("start plugin");
    debug!("proc_mosquitto_auth_plugin_init");

    for (opt_key, opt_value) in opt_map.iter() {
        debug!("opt {},{}", opt_key, opt_value);
    }

    // init an auth logger
    let (log_sender, log_receiver) = channel::<(DateTime<Local>, String)>();
    let log_thread_handler = thread::spawn(move || {
        debug!("start a log thread");
        while let Ok((time, text)) = log_receiver.recv() {
            // write an auth log file
            match OpenOptions::new()
                .append(true)
                .create(true)
                .open(&auth_log_file_name)
            {
                Ok(log_file) => {
                    let mut f = BufWriter::new(log_file);
                    writeln!(f, "{} {}", time.format(LOG_DATE_FORMAT).to_string(), text);
                    while let Ok((time, text)) = log_receiver.try_recv() {
                        writeln!(f, "{} {}", time.format(LOG_DATE_FORMAT).to_string(), text);
                    }
                }
                Err(_e) => continue,
            }
        }
        debug!("stop a log thread");
    });

    let config_info = misc::update_config(config_path);

    let config = Box::new(UserData {
        config_path: config_path.to_string(),
        config_info: RwLock::new(config_info),
        client_map: RwLock::new(HashMap::new()),
        log: Mutex::new(Some(log_sender.clone())),
        log_thread: log_thread_handler,
    });
    unsafe {
        *user_data = Box::into_raw(config);
    }
    MOSQ_ERR_SUCCESS
}

#[no_mangle]
pub extern "C" fn proc_mosquitto_auth_plugin_cleanup(
    user_data: *mut UserData,
    _opts: *const mosquitto_opt,
    _opt_count: c_int,
) -> c_int {
    debug!("proc_mosquitto_auth_plugin_cleanup");
    info!("stop plugin");
    let user_data = unsafe { Box::from_raw(user_data) };
    {
        user_data.log.lock().unwrap().take();
    }
    user_data.log_thread.join().unwrap();

    MOSQ_ERR_SUCCESS
}

#[no_mangle]
pub extern "C" fn proc_mosquitto_auth_security_init(
    user_data: *const UserData,
    _opts: *const mosquitto_opt,
    _opt_count: c_int,
    reload: c_uint,
) -> c_int {
    let user_data: &UserData = unsafe { &*user_data };
    debug!("proc_mosquitto_auth_security_init");
    if reload != 0 {
        misc::no_check_config_update(&user_data);
    }
    MOSQ_ERR_SUCCESS
}

#[no_mangle]
pub extern "C" fn proc_mosquitto_auth_security_cleanup(
    _user_data: *const UserData,
    _opts: *const mosquitto_opt,
    _opt_count: c_int,
    _reload: c_uint,
) -> c_int {
    debug!("proc_mosquitto_auth_security_cleanup");
    MOSQ_ERR_SUCCESS
}

#[no_mangle]
pub extern "C" fn proc_mosquitto_auth_unpwd_check_v2(
    user_data: *const UserData,
    username: *const c_char,
    _password: *const c_char,
) -> c_int {
    debug!("proc_mosquitto_auth_unpwd_check_v2");
    let user_data: &UserData = unsafe { &*user_data };
    proc_mosquitto_auth_unpwd_check(user_data, username)
}

#[no_mangle]
pub extern "C" fn proc_mosquitto_auth_unpwd_check_v3(
    user_data: *const UserData,
    client: *const mosquitto,
    username: *const c_char,
    _password: *const c_char,
) -> c_int {
    debug!("proc_mosquitto_auth_unpwd_check_v3");
    let user_data: &UserData = unsafe { &*user_data };
    let result = proc_mosquitto_auth_unpwd_check(user_data, username);

    // save username
    let mut client_map = user_data.client_map.write().unwrap();
    if result == MOSQ_ERR_SUCCESS {
        let username = unsafe { CStr::from_ptr(username) };
        client_map.insert(client, username.to_string_lossy().to_string());
    } else {
        client_map.remove(&client);
    }
    result
}

fn proc_mosquitto_auth_unpwd_check(user_data: &UserData, token: *const c_char) -> c_int {
    debug!("proc_mosquitto_auth_unpwd_check_v2");
    misc::check_config_update(&user_data);
    if token == NULL {
        return MOSQ_ERR_AUTH;
    }
    let token = match unsafe { CStr::from_ptr(token) }.to_str() {
        Ok(x) => x,
        Err(e) => {
            warn!("illegal jwt:{}", e);
            return MOSQ_ERR_AUTH;
        }
    };
    debug!("jwt {}", token);
    let config_info = user_data.config_info.read().unwrap();
    let config = match config_info.config {
        Some(ref x) => x,
        None => {
            return MOSQ_ERR_AUTH;
        }
    };

    let token_data = match decode::<Value>(
        token.as_ref(),
        config.key.as_bytes(),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(x) => x,
        Err(e) => {
            warn!("jwt:{}, {}", token, e);
            return MOSQ_ERR_AUTH;
        }
    };
    debug!("claims:{}", token_data.claims);

    let sub = token_data
        .claims
        .get("sub")
        .and_then(|x| x.as_str())
        .unwrap_or("no sub");
    let log = user_data.log.lock().unwrap();
    if let Some(ref log) = *log {
        let mut output = String::new();
        fmt::write(&mut output, format_args!("AUTH {}", sub)).unwrap();
        log.send((Local::now(), output)).unwrap();
    };
    MOSQ_ERR_SUCCESS
}

#[no_mangle]
pub extern "C" fn proc_mosquitto_auth_acl_check_v2(
    user_data: *const UserData,
    _clientid: *const c_char,
    username: *const c_char,
    topic: *const c_char,
    access: c_int,
) -> c_int {
    debug!("proc_mosquitto_auth_acl_check_v2");
    if username == NULL {
        return MOSQ_ERR_ACL_DENIED;
    }
    let username = match unsafe { CStr::from_ptr(username) }.to_str() {
        Ok(x) => x,
        Err(_e) => {
            return MOSQ_ERR_ACL_DENIED;
        }
    };
    proc_mosquitto_auth_acl_check(user_data, username, topic, access)
}

#[no_mangle]
pub extern "C" fn proc_mosquitto_auth_acl_check_v3(
    user_data: *const UserData,
    access: c_int,
    client: *const mosquitto,
    msg: *const mosquitto_acl_msg,
) -> c_int {
    debug!("proc_mosquitto_auth_acl_check_v3");
    let user_data: &UserData = unsafe { &*user_data };
    let client_map = user_data.client_map.read().unwrap();
    match client_map.get(&client) {
        Some(username) => {
            proc_mosquitto_auth_acl_check(user_data, username, unsafe { (*msg).topic }, access)
        }
        None => MOSQ_ERR_ACL_DENIED,
    }
}

fn proc_mosquitto_auth_acl_check(
    user_data: *const UserData,
    token: &str,
    topic: *const c_char,
    access: c_int,
) -> c_int {
    let user_data: &UserData = unsafe { &*user_data };
    misc::check_config_update(&user_data);
    let topic = match unsafe { CStr::from_ptr(topic) }.to_str() {
        Ok(x) => x,
        Err(e) => {
            warn!("jwt:{}, illegal topic:{}", token, e);
            return MOSQ_ERR_ACL_DENIED;
        }
    };
    debug!("jwt {}", token);
    debug!("topic {}", topic);

    let config_info = user_data.config_info.read().unwrap();
    let config = match config_info.config {
        Some(ref x) => x,
        None => {
            return MOSQ_ERR_ACL_DENIED;
        }
    };

    let token_data = match decode::<Value>(
        token.as_ref(),
        config.key.as_bytes(),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(x) => x,
        Err(e) => {
            warn!("jwt:{}, {}", token, e);
            return MOSQ_ERR_ACL_DENIED;
        }
    };
    let sub = token_data
        .claims
        .get("sub")
        .and_then(|x| x.as_str())
        .unwrap_or("no sub");
    let (db_name, subset_name) = if let Some(caps) = REGEX_PATH_TRANSACTION.captures(topic) {
        (percent_decode(caps.get(1).unwrap().as_str().as_bytes()).decode_utf8().unwrap(), None)
    } else if let Some(caps) = REGEX_PATH_SUBSET_TRANSACTION.captures(topic) {
        (
            percent_decode(caps.get(1).unwrap().as_str().as_bytes()).decode_utf8().unwrap(),
            Some(percent_decode(caps.get(2).unwrap().as_str().as_bytes()).decode_utf8().unwrap()),
        )
    } else {
        warn!("sub:{}, illegal topic:{}", sub, topic);
        return MOSQ_ERR_ACL_DENIED;
    };
    for acl in &config.acl {
        if acl.resource.resource_type != "dadget" {
            continue;
        };
        let path = &acl.resource.path;
        if path.check_path(db_name.as_ref(), subset_name.as_ref().map(|x| x.as_ref())) {
            let result = check_accesses(&token_data.claims, &acl.resource.accesses, access);
            if result == MOSQ_ERR_SUCCESS {
                let log = user_data.log.lock().unwrap();
                if let Some(ref log) = *log {
                    let mut output = String::new();
                    let mode = match access {
                        MOSQ_ACL_READ => "READ",
                        MOSQ_ACL_WRITE => "WRITE",
                        MOSQ_ACL_SUBSCRIBE => "SUBSCRIBE",
                        _ => "ANOTHER",
                    };
                    fmt::write(&mut output, format_args!("{} {}", mode, sub)).unwrap();
                    log.send((Local::now(), output)).unwrap();
                };
                return result;
            }
        }
    }
    warn!("sub:{}, no permission topic:{}", sub, topic);
    MOSQ_ERR_ACL_DENIED
}

impl config::ResourcePath {
    fn check_path(&self, db_name: &str, subset_name: Option<&str>) -> bool {
        match self {
            config::ResourcePath::Str(x) => match x.len() {
                0 => true,
                1 => x[0] == db_name,
                2 => {
                    x[0] == db_name && match subset_name {
                        Some(subset_name) => x[1] == *subset_name,
                        None => false,
                    }
                }
                _ => false,
            },
            config::ResourcePath::Regex(x) => match x.len() {
                1 => x[0].is_match(db_name),
                2 => {
                    x[0].is_match(db_name) && match subset_name {
                        Some(subset_name) => x[1].is_match(subset_name),
                        None => false,
                    }
                }
                _ => false,
            },
        }
    }
}

fn check_accesses(
    claims: &serde_json::Value,
    accesses: &Vec<config::Accesses>,
    access: c_int,
) -> c_int {
    if access == MOSQ_ACL_SUBSCRIBE {
        return MOSQ_ERR_SUCCESS;
    }
    for config_access in accesses {
        if match_access(config_access, access) && match_claims(config_access, claims) {
            return MOSQ_ERR_SUCCESS;
        }
    }
    MOSQ_ERR_ACL_DENIED
}

fn match_access(config_access: &config::Accesses, access: c_int) -> bool {
    if access == MOSQ_ACL_READ && config_access.operation.eq_ignore_ascii_case("READ") {
        return true;
    }
    if access == MOSQ_ACL_WRITE && config_access.operation.eq_ignore_ascii_case("WRITE") {
        return true;
    }
    if config_access.operation == "*" {
        return true;
    }
    return false;
}

fn match_claims(config_access: &config::Accesses, claims: &serde_json::Value) -> bool {
    match config_access.subject {
        None => true,
        Some(ref subject_list) => {
            subject_list
                .iter()
                .all(|(key, regex)| match claims[key].as_str() {
                    None => false,
                    Some(x) => regex.0.is_match(x),
                })
        }
    }
}
