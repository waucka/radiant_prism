use libc;

use std::ffi::CStr;
use std::str::Utf8Error;
use std::ptr;

pub enum FlatpakError {
    None,
    Incomplete,
    Unknown,
}

pub struct FlatpakApp {
  pub origin: String,
  pub latest_commit: String,
  pub commit: String,
}

const FLATPAK_APPS_ERR_NONE: i32 =       0;
const FLATPAK_APPS_ERR_INCOMPLETE: i32 = 1;

#[allow(non_camel_case_types)]
enum flatpak_app_t {}
#[allow(non_camel_case_types)]
enum flatpak_app_list_t {}

extern {
    fn flatpak_app_get_origin(app: *const flatpak_app_t) -> *const libc::c_char;
    fn flatpak_app_get_latest_commit(app: *const flatpak_app_t) -> *const libc::c_char;
    fn flatpak_app_get_commit(app: *const flatpak_app_t) -> *const libc::c_char;

    fn enum_flatpak_apps(apps: *mut *mut flatpak_app_list_t) -> libc::c_int;
    fn flatpak_apps_list_iter_start(apps: *mut flatpak_app_list_t) -> *const flatpak_app_t;
    fn flatpak_apps_list_iter_next(apps: *mut flatpak_app_list_t) -> *const flatpak_app_t;
    fn free_flatpak_apps(apps: *mut flatpak_app_list_t) -> libc::c_int;
}

unsafe fn convert_flatpak_app_struct(app: *const flatpak_app_t) -> Result<FlatpakApp, Utf8Error> {
    let origin = CStr::from_ptr(flatpak_app_get_origin(app));
    let latest_commit = CStr::from_ptr(flatpak_app_get_latest_commit(app));
    let commit = CStr::from_ptr(flatpak_app_get_commit(app));

    Ok(FlatpakApp{
        origin: String::from(origin.to_str()?),
        latest_commit: String::from(latest_commit.to_str()?),
        commit: String::from(commit.to_str()?),
    })
}

pub fn get_flatpak_installed_packages() -> (Vec<FlatpakApp>, FlatpakError) {
    let mut apps_vec = Vec::new();
    let mut err = FlatpakError::None;

    unsafe {
        let mut apps: *mut flatpak_app_list_t = ptr::null_mut();
        let result = enum_flatpak_apps(&mut apps as *mut *mut flatpak_app_list_t);
        if result == FLATPAK_APPS_ERR_INCOMPLETE {
            err = FlatpakError::Incomplete;
        } else if result != FLATPAK_APPS_ERR_NONE {
            err = FlatpakError::Unknown;
        }
        let mut app = flatpak_apps_list_iter_start(apps);
        while !app.is_null() {
            match convert_flatpak_app_struct(app) {
                Ok(fp_app) => apps_vec.push(fp_app),
                Err(_) => err = FlatpakError::Incomplete,
            }
            app = flatpak_apps_list_iter_next(apps);
        }
        free_flatpak_apps(apps);
    }

    return (apps_vec, err);
}
