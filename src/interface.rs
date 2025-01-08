
pub fn index_to_name(index: libc::c_uint) -> Result<String, std::io::Error> {
    let ifname_buf = [0u8; libc::IFNAMSIZ];
    let ret = unsafe { libc::if_indextoname(index, ifname_buf.as_ptr() as *mut libc::c_char) };
    if ret.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    
    let name = unsafe { std::ffi::CStr::from_ptr(ret as *const libc::c_char) };
    Ok(name.to_string_lossy().into_owned())
}

pub fn name_to_index(name: &str) -> Result<libc::c_uint, std::io::Error> {
    let index = unsafe { libc::if_nametoindex(name.as_ptr() as *const libc::c_char) };
    if index == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(index)
}
