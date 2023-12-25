use scanf::sscanf;
use std::fs::read_to_string;

pub fn boot_time_get_ns() -> Result<u64, u64> {
    let result = match read_to_string("/proc/uptime") {
        Ok(line) => { 
            let mut boot_time_ns = 0.0;
            sscanf!(&line, "{} {}", boot_time_ns);
            (boot_time_ns * 1000000000.0) as u64
        },
        Err(_) => 0,
    };
    Ok(result)
}
