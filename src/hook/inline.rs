use libc::uintptr_t;

pub struct Hook {
    // in
    func_addr: uintptr_t,
    origin_addr: uintptr_t,
    replace_addr: uintptr_t,
}

impl Hook {
    pub fn new(func: uintptr_t, replace: uintptr_t) -> Self {
        Hook {
            func_addr: func,
            origin_addr: func,
            replace_addr: replace,
        }
    }
}
