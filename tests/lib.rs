extern crate chipin_mqtt_auth_plugin;
extern crate jsonwebtoken;
#[macro_use]
extern crate serde_derive;

use chipin_mqtt_auth_plugin::*;
use jsonwebtoken::{encode, Header};
use std::ffi::CString;
use std::os::raw::c_int;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: &'static str,
    xattr: &'static str,
    exp: u64,
}

fn unix_time() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}
#[test]
fn test_proc_mosquitto_auth_plugin_init() {
    let user_data: Box<*mut UserData> = Box::new(0 as *mut UserData);
    let ptr_user_data = Box::into_raw(user_data);

    let mut acl_file = std::env::current_dir().unwrap();
    acl_file.push("samples");
    acl_file.push("acl.json");
    println!("{:?}", acl_file);
    let mut mosquitto_opt: Vec<mosquitto_opt> = Vec::new();
    let config_key = CString::new(::DEFAULT_CONFIG_PATH_OPT_KEY).unwrap();
    let file_path = CString::new(acl_file.to_str().unwrap()).unwrap();
    mosquitto_opt.push(::mosquitto_opt {
        key: config_key.as_ptr(),
        value: file_path.as_ptr(),
    });
    ::proc_mosquitto_auth_plugin_init(ptr_user_data, &mosquitto_opt[0], mosquitto_opt.len() as i32);

    ::proc_mosquitto_auth_security_init(
        unsafe { *ptr_user_data },
        &mosquitto_opt[0],
        mosquitto_opt.len() as i32,
        1,
    );

    assert_eq!(
        check1(
            ptr_user_data,
            "/m/d/db2/transaction",
            ::MOSQ_ACL_WRITE,
            &Claims {
                sub: "xxxx@example.jp",
                xattr: "33333",
                exp: unix_time() + 10,
            },
        ),
        ::MOSQ_ERR_SUCCESS
    );

    assert_eq!(
        check1(
            ptr_user_data,
            "/m/d/dddd/transaction",
            ::MOSQ_ACL_READ,
            &Claims {
                sub: "xxxx@example.jp",
                xattr: "33333",
                exp: unix_time() + 10,
            },
        ),
        ::MOSQ_ERR_ACL_DENIED
    );

    assert_eq!(
        check1(
            ptr_user_data,
            "/m/d/dbname1/subset/sub1/transaction",
            ::MOSQ_ACL_READ,
            &Claims {
                sub: "aaa@example.jp",
                xattr: "33333",
                exp: unix_time() + 10,
            },
        ),
        ::MOSQ_ERR_SUCCESS
    );

    assert_eq!(
        check1(
            ptr_user_data,
            "/m/d/dbname1/subset/sub1/transaction",
            ::MOSQ_ACL_WRITE,
            &Claims {
                sub: "aaa@example.jp",
                xattr: "33333",
                exp: unix_time() + 10,
            },
        ),
        ::MOSQ_ERR_ACL_DENIED
    );

    assert_eq!(
        check1(
            ptr_user_data,
            "/m/d/dbname1/subset/sub1/transaction",
            ::MOSQ_ACL_READ,
            &Claims {
                sub: "xxxx@example.jp",
                xattr: "33333",
                exp: unix_time() + 10,
            },
        ),
        ::MOSQ_ERR_SUCCESS
    );

    assert_eq!(
        check1(
            ptr_user_data,
            "/m/d/dbname1/subset/sub1/transaction",
            ::MOSQ_ACL_WRITE,
            &Claims {
                sub: "xxxx@example.jp",
                xattr: "33333",
                exp: unix_time() + 10,
            },
        ),
        ::MOSQ_ERR_SUCCESS
    );

    assert_eq!(
        check1(
            ptr_user_data,
            "/mqtt_test/dddd",
            ::MOSQ_ACL_WRITE,
            &Claims {
                sub: "xxxx@example.jp",
                xattr: "33333",
                exp: unix_time() + 10,
            },
        ),
        ::MOSQ_ERR_SUCCESS
    );

    assert_eq!(
        check1(
            ptr_user_data,
            "/mqtt_testa",
            ::MOSQ_ACL_WRITE,
            &Claims {
                sub: "xxxx@example.jp",
                xattr: "33333",
                exp: unix_time() + 10,
            },
        ),
        ::MOSQ_ERR_ACL_DENIED
    );

    assert_eq!(
        check1(
            ptr_user_data,
            "/mqtt_test2",
            ::MOSQ_ACL_WRITE,
            &Claims {
                sub: "xxxx@example.jp",
                xattr: "33333",
                exp: unix_time() + 10,
            },
        ),
        ::MOSQ_ERR_SUCCESS
    );

    assert_eq!(
        check1(
            ptr_user_data,
            "/dummy/mqtt_test2",
            ::MOSQ_ACL_WRITE,
            &Claims {
                sub: "xxxx@example.jp",
                xattr: "33333",
                exp: unix_time() + 10,
            },
        ),
        ::MOSQ_ERR_ACL_DENIED
    );

    ::proc_mosquitto_auth_plugin_cleanup(
        unsafe { *ptr_user_data },
        &mosquitto_opt[0],
        mosquitto_opt.len() as i32,
    );
    unsafe { drop(Box::from_raw(ptr_user_data)) }
}

fn check1(ptr_user_data: *mut *mut UserData, topic: &str, access: c_int, claims: &Claims) -> c_int {
    let token = encode(&Header::default(), &claims, "q6r2MewgJmLc".as_ref()).unwrap();
    let token = CString::new(token).expect("error");

    ::proc_mosquitto_auth_unpwd_check_v2(unsafe { *ptr_user_data }, token.as_ptr(), ::NULL);

    let topic = CString::new(topic).expect("error");

    let start = Instant::now();
    let result = ::proc_mosquitto_auth_acl_check_v2(
        unsafe { *ptr_user_data },
        ::NULL,
        token.as_ptr(),
        topic.as_ptr(),
        access,
    );
    let end = start.elapsed();
    println!("{} nano sec", end.subsec_nanos());
    result
}
