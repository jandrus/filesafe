// Filesafe - Secure file vault
// Copyright (C) 2023 James Andrus
// Email: jandrus@citadel.edu

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::env::{self, set_current_dir, var};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{stdin, stdout, BufRead, BufReader, Write};
use std::net::{IpAddr, TcpStream};
use std::path::Path;
use std::process;
use std::str::from_utf8;

use anyhow::{bail, ensure, Context, Result};
use base64::encode;
use chrono::{Local, NaiveDateTime};
use clap::{Arg, ArgMatches, Command};
use ini::Ini;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use zeroize::Zeroize;

struct ServerPK {
    key: RsaPublicKey,
}

struct ClientParams {
    server_ip: String,
    server_port: String,
}

// EXIT CODES
const EX_USAGE: i32 = 64;
const EX_DATAERR: i32 = 65;
const EX_NOHOST: i32 = 68;
const EX_UNAVAILABLE: i32 = 69;
const EX_SOFTWARE: i32 = 70;
const EX_NOPERM: i32 = 77;
// FILES
const FILESAFE_LOG: &str = "filesafe.log";
const FILESAFE_CONF: &str = "filesafe.ini";
// REQUEST MSGS
const REQUEST_UNLOCK: &str = "601";
const REQUEST_LOCK: &str = "602";
const REQUEST_EXIT: &str = "603";
// STATUS MSGS
const STATUS_IS_LOCKED: &str = "101";
const STATUS_IS_UNLOCKED: &str = "102";
const STATUS_IS_EMPTY: &str = "103";
const STATUS_OK: &str = "200";
const STATUS_IN_ACTION: &str = "201";
const STATUS_ERR: &str = "418";
const STATUS_AUTH_BAD: &str = "401";
const STATUS_GOOD_KEY: &str = "211";

fn main() {
    clear_screen();
    let safe_dir = match get_filesafe_dir() {
        Ok(s) => s,
        Err(e) => {
            let err_str = format!("Error: {}", e);
            log_event(&err_str);
            process::exit(EX_NOPERM);
        }
    };
    let current_dir = env::current_dir()
        .expect("Error getting current working directory")
        .to_str()
        .expect("Error getting current working directory")
        .to_string();
    match set_current_dir(&safe_dir) {
        Ok(_) => (),
        Err(e) => {
            let err_str = format!("Failed to set proper working directory: {}", e);
            log_event(&err_str);
            process::exit(EX_NOPERM);
        }
    };
    log_event("Client Startup");
    let matches = get_matches();
    let client_params = match get_client_params(matches.clone(), current_dir, safe_dir) {
        Ok(cp) => cp,
        Err(e) => {
            let err_str = format!("Error: {e}");
            log_event(&err_str);
            process::exit(EX_USAGE);
        }
    };
    let ip_str = format!("{}:{}", client_params.server_ip, client_params.server_port);
    let stream = match TcpStream::connect(&ip_str) {
        Ok(t) => t,
        Err(e) => {
            let err_str = format!("Error failed to connect to [{ip_str}]: {e}");
            log_event(&err_str);
            process::exit(EX_NOHOST);
        }
    };
    // NOTE: step 1
    let server_pk = match process_server_keys(&stream) {
        Ok(pk) => pk,
        Err(e) => {
            let err_str = format!("Error failed to process server keys: {e}");
            log_event(&err_str);
            match send_msg(STATUS_ERR, &stream) {
                Ok(_) => (),
                Err(e) => {
                    let err_str = format!("Error failed to send BAD KEY: {e}");
                    log_event(&err_str);
                }
            }
            process::exit(EX_DATAERR);
        }
    };
    let event = format!("RSA Key received from {}", stream.peer_addr().unwrap());
    log_event(&event);
    // NOTE step 2
    match send_msg(STATUS_GOOD_KEY, &stream) {
        Ok(_) => (),
        Err(e) => {
            let err_str = format!("Error failed to send GOOD KEY: {e}");
            log_event(&err_str);
            process::exit(EX_NOHOST);
        }
    };
    // NOTE step 3
    let mut enc_pass: String;
    {
        // minimize time clear text password is in memory
        let pw = match rpassword::prompt_password("Enter password: ") {
            Ok(p) => p,
            Err(e) => {
                let err_str = format!("Error: {e}");
                log_event(&err_str);
                process::exit(EX_DATAERR);
            }
        };
        enc_pass = match encrypt_msg(&pw, server_pk) {
            Ok(s) => s,
            Err(e) => {
                let err_str = format!("Error: {e}");
                log_event(&err_str);
                process::exit(EX_SOFTWARE);
            }
        };
    }
    match send_msg(&enc_pass, &stream) {
        Ok(_) => (),
        Err(e) => {
            let err_str = format!("Error: {}", e);
            log_event(&err_str);
            process::exit(EX_NOHOST);
        }
    }
    enc_pass.zeroize();
    // NOTE: step 4
    let filesafe_status = match recv_msg(&stream) {
        Ok(s) => s,
        Err(e) => {
            let err_msg = format!("Error with {}: {} ", stream.peer_addr().unwrap(), e);
            log_event(&err_msg);
            drop(stream);
            process::exit(EX_NOHOST);
        }
    };
    if filesafe_status == STATUS_AUTH_BAD {
        log_event("Authentication failed");
        drop(stream);
        process::exit(EX_USAGE);
    }
    if filesafe_status == STATUS_IS_EMPTY {
        log_event("Filesafe is empty, nothing to do");
        drop(stream);
        return;
    }
    if filesafe_status != STATUS_IS_LOCKED && filesafe_status != STATUS_IS_UNLOCKED {
        let err_msg = format!(
            "Unexpected status message from server [{}]: {}",
            stream.peer_addr().unwrap(),
            &filesafe_status
        );
        log_event(&err_msg);
        drop(stream);
        process::exit(EX_UNAVAILABLE);
    }
    log_event("Authentication successful");
    let action: String;
    if filesafe_status == STATUS_IS_LOCKED {
        log_event("Filesafe is locked");
        if matches.get_flag("lock") {
            println!("Filesafe is already locked");
            action = "x".to_string();
        } else if matches.get_flag("unlock") {
            action = REQUEST_UNLOCK.to_string();
        } else {
            action = match get_client_action(0, &filesafe_status) {
                Ok(s) => s,
                Err(e) => {
                    let err_msg = format!("Error with user input {} ", e);
                    log_event(&err_msg);
                    drop(stream);
                    process::exit(EX_USAGE);
                }
            };
        }
    } else {
        log_event("Filesafe is unlocked");
        if matches.get_flag("unlock") {
            println!("Filesafe is already unlocked");
            action = "x".to_string();
        } else if matches.get_flag("lock") {
            action = REQUEST_LOCK.to_string();
        } else {
            action = match get_client_action(0, &filesafe_status) {
                Ok(s) => s,
                Err(e) => {
                    let err_msg = format!("Error with user input {} ", e);
                    log_event(&err_msg);
                    drop(stream);
                    process::exit(EX_USAGE);
                }
            };
        }
    }
    if action == "x" {
        match send_msg(REQUEST_EXIT, &stream) {
            Ok(_) => (),
            Err(e) => {
                let err_msg = format!("Error with {}: {} ", stream.peer_addr().unwrap(), e);
                log_event(&err_msg);
                drop(stream);
                process::exit(EX_NOHOST);
            }
        };
        drop(stream);
        return;
    }
    match send_msg(&action, &stream) {
        Ok(_) => (),
        Err(e) => {
            let err_msg = format!("Error with {}: {} ", stream.peer_addr().unwrap(), e);
            log_event(&err_msg);
            drop(stream);
            process::exit(EX_NOHOST);
        }
    };
    let server_status = match recv_msg(&stream) {
        Ok(s) => s,
        Err(e) => {
            let err_msg = format!("Error with {}: {} ", stream.peer_addr().unwrap(), e);
            log_event(&err_msg);
            drop(stream);
            process::exit(EX_NOHOST);
        }
    };
    if server_status == STATUS_OK {
        if action == REQUEST_LOCK {
            log_event("Lock OK, Filesafe is locking");
        }
        if action == REQUEST_UNLOCK {
            log_event("Unlock OK, Filesafe is unlocking");
        }
    } else {
        if server_status == STATUS_IN_ACTION {
            log_event("Server is busy");
        } else {
            let event = format!("Server Error: [{}]", server_status);
            log_event(&event);
        }
    }
    drop(stream);
}

fn get_client_action(mut num_tries: usize, filesafe_status: &str) -> Result<String> {
    ensure!(num_tries < 3, "Max attempts exceeded [get_client_action]");
    if filesafe_status == STATUS_IS_LOCKED {
        println!("u -> Unlock filesafe\nx -> Exit");
        let mut ans = String::new();
        print!("Choose action? [u/x]: ");
        let _ = stdout().flush();
        let _byt = stdin().read_line(&mut ans)?;
        let processed_ans = &ans.trim().to_string().to_lowercase();
        if processed_ans == "u" {
            return Ok(REQUEST_UNLOCK.to_string());
        }
        if processed_ans == "x" {
            return Ok("x".to_string());
        }
        println!("Invalid input");
        num_tries += 1;
        return get_client_action(num_tries, filesafe_status);
    }
    println!("l -> Lock filesafe\nx -> Exit");
    let mut ans = String::new();
    print!("Choose action? [l/x]: ");
    let _ = stdout().flush();
    let _byt = stdin().read_line(&mut ans)?;
    let processed_ans = &ans.trim().to_string().to_lowercase();
    if processed_ans == "l" {
        return Ok(REQUEST_LOCK.to_string());
    }
    if processed_ans == "x" {
        return Ok("x".to_string());
    }
    println!("Invalid input");
    num_tries += 1;
    return get_client_action(num_tries, filesafe_status);
}

fn encrypt_msg(msg: &str, server_pk: ServerPK) -> Result<String> {
    let mut rng = rand::thread_rng();
    let data = msg.as_bytes();
    let padding = PaddingScheme::new_pkcs1v15_encrypt();
    let enc_data = server_pk.key.encrypt(&mut rng, padding, &data[..])?;
    Ok(encode(enc_data))
}

fn process_server_keys(stream: &TcpStream) -> Result<ServerPK> {
    let server_key = recv_msg(stream)?;
    match RsaPublicKey::from_pkcs1_pem(&server_key) {
        Ok(k) => Ok(ServerPK { key: k }),
        Err(_) => bail!("Unable to parse Server's public key"),
    }
}

fn send_msg(msg: &str, mut stream: &TcpStream) -> Result<()> {
    stream.write_all(msg.as_bytes())?;
    Ok(())
}

fn recv_msg(stream: &TcpStream) -> Result<String> {
    let mut reader = BufReader::new(stream);
    let received: Vec<u8> = reader.fill_buf().unwrap().to_vec();
    reader.consume(received.len());
    let msg = from_utf8(&received)?.to_owned();
    Ok(msg)
}

fn log_event(e: &str) {
    let now_ts = Local::now().timestamp() - 18000;
    let now = NaiveDateTime::from_timestamp_opt(now_ts, 0).unwrap();
    let event_msg = format!("[{now}] {e}\n");
    print!("{}", event_msg);
    if Path::new(FILESAFE_LOG).exists() {
        let mut f = OpenOptions::new()
            .append(true)
            .open(FILESAFE_LOG)
            .expect("Unable to open log file for appending.");
        f.write_all(event_msg.as_bytes())
            .expect("Unable to append to log.");
    } else {
        let mut f = File::create(FILESAFE_LOG).unwrap();
        f.write_all(event_msg.as_bytes())
            .expect("Unable to write initial event to log.");
    }
}

fn get_filesafe_dir() -> Result<String> {
    match var("HOME") {
        Ok(val) => {
            let filesafe_dir = format!("{}/.config/filesafe", val);
            if !Path::new(&filesafe_dir).exists() {
                create_dir_all(&filesafe_dir)
                    .with_context(|| "Failed to create Filesafe directory")?;
                println!("Filesafe directory created [{}]", filesafe_dir);
            }
            return Ok(filesafe_dir);
        }
        Err(e) => {
            bail!("Couldn't find users $HOME directory: {e}");
        }
    }
}

fn clear_screen() {
    print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
}

fn get_matches() -> ArgMatches {
    Command::new("filesafe")
        .about("Filesafe client program")
        .version("0.1.0")
        .author("Zero Cool")
        .arg_required_else_help(false)
        .arg(Arg::new("unlock")
             .short('u')
             .long("unlock")
             .help("Send unlock signal to filesafe server specified in config file or via arguments")
             .conflicts_with("lock")
             .required(false)
             .action(clap::ArgAction::SetTrue))
        .arg(Arg::new("lock")
             .short('l')
             .long("lock")
             .help("Send lock signal to filesafe server specified in config file or via arguments")
             .conflicts_with("unlock")
             .required(false)
             .action(clap::ArgAction::SetTrue))
        .arg(Arg::new("port")
             .short('p')
             .long("port")
             .help("Specify port for filesafe server")
             .required(false)
             .action(clap::ArgAction::Set)
             .num_args(1),
        )
        .arg(Arg::new("address")
             .short('a')
             .long("address")
             .help("Specify address for filesafe server")
             .required(false)
             .action(clap::ArgAction::Set)
             .num_args(1),
        )
        .arg(Arg::new("config")
             .short('c')
             .long("config")
             .help("Specify configuration file for filesafe client")
             .required(false)
             .action(clap::ArgAction::Set)
             .num_args(1),
        )
        .get_matches()
}

fn get_client_params(
    matches: ArgMatches,
    current_dir: String,
    safe_dir: String,
) -> Result<ClientParams> {
    // set proper config file
    let conf_file: &str;
    match matches.value_source("config") {
        Some(_) => {
            conf_file = matches
                .get_one::<String>("config")
                .expect("Args do not contain config file");
            set_current_dir(&current_dir)?;
        }
        None => {
            conf_file = FILESAFE_CONF;
        }
    };
    let mut client_params = ClientParams {
        server_ip: "0.0.0.0".to_string(),
        server_port: "0".to_string(),
    };
    if Path::new(conf_file).exists() {
        client_params = get_client_params_from_conf(conf_file)?;
    }
    set_current_dir(&safe_dir)?;
    match matches.value_source("port") {
        Some(_) => {
            client_params.server_port = matches
                .get_one::<String>("port")
                .expect("Args do not contain port")
                .to_string();
        }
        None => (),
    }
    match client_params.server_port.parse::<usize>() {
        Ok(n) => {
            ensure!(n < 65535, "Port out of bounds");
        }
        Err(e) => {
            bail!("Port out of bounds: {}", e);
        }
    }
    match matches.value_source("address") {
        Some(_) => {
            client_params.server_ip = matches
                .get_one::<String>("address")
                .expect("Args do not contain address")
                .to_string();
        }
        None => (),
    }
    match client_params.server_ip.parse::<IpAddr>() {
        Ok(_) => (),
        Err(e) => {
            bail!("Configuration file misconfigured [server_ip]: {}", e);
        }
    }
    ensure!(
        client_params.server_ip != "0.0.0.0",
        "Configuration file misconfigured [server_ip]"
    );
    Ok(client_params)
}

fn get_client_params_from_conf(conf_file: &str) -> Result<ClientParams> {
    let conf = Ini::load_from_file(conf_file)?;
    let section = match conf.section(Some("CLIENT")) {
        Some(s) => s,
        None => bail!("Configuration file is misconfigured [section::CLIENT]"),
    };
    let server_port = match section.get("server_port") {
        Some(s) => s.to_string(),
        None => "7878".to_string(),
    };
    let server_ip = match section.get("server_ip") {
        Some(s) => s.to_string(),
        None => "0.0.0.0".to_string(),
    };
    Ok(ClientParams {
        server_ip,
        server_port,
    })
}
