use libc;
use std;

pub fn gethostname() -> std::io::Result<String> {
    unsafe {
        let mut name = Vec::new();
        name.resize(65, 0u8);

        let ptr = name.as_mut_ptr() as *mut libc::c_char;
        let cap = name.len() as libc::size_t;

        let ret = libc::gethostname(ptr, cap);
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let len = name.iter().position(|byte| *byte == 0).unwrap_or(cap);
        name.resize(len, 0);

        Ok(String::from_utf8_lossy(&name).into_owned())
    }
}
