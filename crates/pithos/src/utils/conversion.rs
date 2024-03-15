use tracing::Level;

pub fn evaluate_log_level(input: Option<String>) -> Level {
    if let Some(log_level) = input {
        match log_level.as_str() {
            "INFO" => Level::INFO,
            "WARN" => Level::WARN,
            "ERROR" => Level::ERROR,
            "DEBUG" => Level::DEBUG,
            "TRACE" => Level::TRACE,
            _ => Level::INFO,
        }
    } else {
        Level::INFO
    }
}

pub fn _to_hex_string(bytes: Vec<u8>) -> String {
    let hex_str: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    hex_str.join("")
}
