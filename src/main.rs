use std::fs;
use std::path::Path;
use std::io;
use std::thread;
use std::time::Duration;
use std::process::Command;

fn pattern_to_bytes(pattern: &str) -> Vec<Option<u8>> {
    pattern
        .split_whitespace()
        .map(|byte| {
            if byte == "?" {
                None
            } else {
                Some(u8::from_str_radix(byte, 16).unwrap_or(0))
            }
        })
        .collect()
}

pub unsafe fn pattern_scan(base: usize, size: usize, pattern: &str, num: usize) -> Option<*mut u8> {
    unsafe {
        let pattern_bytes = pattern_to_bytes(pattern);
        let pattern_len = pattern_bytes.len();
        let end = size.checked_sub(pattern_len)?;

        let module_slice = std::slice::from_raw_parts(base as *const u8, size);

        let mut match_count = 0;

        for i in 0..end {
            let mut found = true;
            for (j, &expected) in pattern_bytes.iter().enumerate() {
                if let Some(byte) = expected {
                    if module_slice[i + j] != byte {
                        found = false;
                        break;
                    }
                }
            }
            if found {
                if match_count == num {
                    return Some((base + i) as *mut u8);
                }
                match_count += 1;
            }
        }

        None
    }
}

fn main() -> io::Result<()> {
    println!("IDM Tamper Check Bypass Patcher");

    match Command::new("taskkill")
        .args(&["/F", "/IM", "idman.exe"])
        .output() {
        Ok(_) => {},
        Err(_) => {},
    }
    thread::sleep(Duration::from_secs(1));

    let current_dir = std::env::current_dir()?;
    let idm_path = current_dir.join("IDMan.exe");

    if !Path::new(&idm_path).exists() {
        println!("IDMan.exe not found!");
        pause();
        return Ok(());
    }

    let mut exe_content = fs::read(&idm_path)?;

    let backup_path = current_dir.join("IDMan.exe.bak");
    if !Path::new(&backup_path).exists() {
        println!("Backing up IDMan.exe to IDMan.exe.bak");
        fs::write(&backup_path, &exe_content)?;
    }

    let base_addr = exe_content.as_ptr() as usize;
    let size = exe_content.len();

    let pattern = "E8 ? ? ? ? B8 01 00 00 00 9B E9 ? ? ? ? 8D 95";
    let pattern_patched = "90 ? ? ? ? B8 01 00 00 00 9B E9 ? ? ? ? 8D 95";

    let result = unsafe { pattern_scan(base_addr, size, pattern, 0) };

    match result {
        Some(address) => {

            println!("address: 0x{:X}", address as usize);
            let offset = (address as usize) - base_addr;
            exe_content[offset] = 0x90; // nop
            println!("Patch success");
        },
        None => {
            if unsafe { pattern_scan(base_addr, size, pattern_patched, 0) }.is_some() {
                println!("Patch success");
            } else {
                println!("Failed to find pattern");
            }
        }
    }

    let pattern_jz = "74 ? E8 ? ? ? ? 85 C0 0F 84 ? ? ? ? 8B 8E ? ? ? ? 8B D1";
    let pattern_jmp = "EB ? E8 ? ? ? ? 85 C0 0F 84 ? ? ? ? 8B 8E ? ? ? ? 8B D1";

    let result_jz = unsafe { pattern_scan(base_addr, size, pattern_jz, 0) };

    match result_jz {
        Some(address) => {
            println!("address: 0x{:X}", address as usize);
            let offset = (address as usize) - base_addr;
            exe_content[offset] = 0xEB; // jz -> jmp
            println!("Patch success");
        },
        None => {
            if unsafe { pattern_scan(base_addr, size, pattern_jmp, 0) }.is_some() {
                println!("Patch success");
            } else {
                println!("Failed to find pattern");
            }
        }
    }

    fs::write(&idm_path, exe_content)?;

    pause();
    Ok(())
}

fn pause() {
    use std::io::Write;
    print!("Press any key to continue...");
    io::stdout().flush().unwrap();
    let _ = io::stdin().read_line(&mut String::new());
}
