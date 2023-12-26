use scanf::sscanf;
use std::fs::read_to_string;

use trac_common::RSSMember;

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

pub fn get_rss_member_name(member: u64) -> String {
    let rss_member_names = std::collections::HashMap::from([
        (RSSMember::MM_FILEPAGES as u64, String::from("filepages")),
        (RSSMember::MM_ANONPAGES as u64, String::from("anonpages")),
        (RSSMember::MM_SWAPENTS as u64, String::from("swapents")),
        (RSSMember::MM_SHMEMPAGES as u64, String::from("shmempages")),
        (RSSMember::MM_TOTAL as u64, String::from("total")),
    ]);

    rss_member_names.get(&member).unwrap().to_string()
}