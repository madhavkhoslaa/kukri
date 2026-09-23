use std::fs;
use std::io;

pub fn list_interfaces() -> io::Result<Vec<String>> {
    let mut names = fs::read_dir("/sys/class/net/")?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<Vec<_>>>()?;
    names.sort();
    Ok(names)
}
