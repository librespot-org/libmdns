extern crate winapi;
extern crate kernel32;
extern crate socket2;

use std;

pub fn gethostname() -> std::io::Result<String> {
  const MAX_COMPUTERNAME_LENGTH: usize = 15;

  let mut buf = [0 as winapi::CHAR; MAX_COMPUTERNAME_LENGTH + 1];
  let mut len = buf.len() as u32;

  unsafe {
    if kernel32::GetComputerNameA(buf.as_mut_ptr(), &mut len) == 0 {
      return Err(std::io::Error::last_os_error());
    };
  }

  let host: Vec<u8> = buf[0..len as usize]
              .iter()
              .map(|&e| e as u8)
              .collect();

  Ok(String::from_utf8_lossy(&host).into_owned())
}
