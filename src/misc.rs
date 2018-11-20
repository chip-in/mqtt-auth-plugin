use config;
use std::io;
use std::time::SystemTime;

pub fn check_config_update(user_data: &::UserData) {
    if {
        let config_info = user_data.config_info.read().unwrap();
        check_config_update_time(&user_data.config_path, &config_info)
    } {
        let mut config_info = user_data.config_info.write().unwrap();
        if check_config_update_time(&user_data.config_path, &config_info) {
            *config_info = update_config(&user_data.config_path);
        }
    }
}

pub fn no_check_config_update(user_data: &::UserData) {
    let mut config_info = user_data.config_info.write().unwrap();
    if check_config_update_time(&user_data.config_path, &config_info) {
        *config_info = update_config(&user_data.config_path);
    }
}

fn check_config_update_time(config_path: &str, config_info: &::ConfigInfo) -> bool {
    (match config_info.last_check_time.elapsed() {
        Ok(elapsed) => elapsed.as_secs() > ::CONFIG_FILE_CHECK_INTERVAL,
        Err(_e) => false,
    }) && { config_info.file_time != ctime(config_path).unwrap_or(0) }
}

#[cfg(unix)]
fn ctime(file_path: &str) -> io::Result<i64> {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    let meta = fs::metadata(file_path)?;
    Ok(meta.ctime())
}

#[cfg(windows)]
fn ctime(file_path: &str) -> io::Result<i64> {
    use std::fs;
    use std::os::windows::prelude::*;

    let meta = fs::metadata(file_path)?;
    Ok(meta.last_write_time() as i64)
}

pub fn update_config(config_path: &str) -> ::ConfigInfo {
    // load a config file
    let config = match config::read_from_file(config_path) {
        Ok(x) => Some(Box::new(x)),
        Err(e) => {
            error!("{}", e);
            None
        }
    };
    debug!("config {:?}", config);
    let file_time = ctime(config_path).unwrap_or(0);

    ::ConfigInfo {
        last_check_time: SystemTime::now(),
        file_time,
        config,
    }
}
