//! 파일을 고르는 Windows 공용 dialog.

use winsafe::{self as w, co, prelude::*};

/// 이미 있는 파일 하나를 고르게 한다. 취소하면 `None`이다.
pub fn open(owner: &w::HWND, file_types: &[(&str, &str)]) -> w::AnyResult<Option<String>> {
    let dialog = w::CoCreateInstance::<w::IFileOpenDialog>(
        &co::CLSID::FileOpenDialog,
        None::<&w::IUnknown>,
        co::CLSCTX::INPROC_SERVER,
    )?;
    dialog.SetOptions(dialog.GetOptions()? | co::FOS::FORCEFILESYSTEM | co::FOS::FILEMUSTEXIST)?;
    dialog.SetFileTypes(file_types)?;
    dialog.SetFileTypeIndex(1)?;
    if !dialog.Show(owner)? {
        return Ok(None);
    }
    Ok(Some(
        dialog.GetResult()?.GetDisplayName(co::SIGDN::FILESYSPATH)?,
    ))
}

/// 저장할 파일 이름을 정하게 한다. 이미 있는 파일을 고르면 dialog가 덮어쓸지 묻는다.
pub fn save(
    owner: &w::HWND,
    file_types: &[(&str, &str)],
    default_extension: &str,
) -> w::AnyResult<Option<String>> {
    let dialog = w::CoCreateInstance::<w::IFileSaveDialog>(
        &co::CLSID::FileSaveDialog,
        None::<&w::IUnknown>,
        co::CLSCTX::INPROC_SERVER,
    )?;
    dialog.SetOptions(dialog.GetOptions()? | co::FOS::FORCEFILESYSTEM)?;
    dialog.SetFileTypes(file_types)?;
    dialog.SetFileTypeIndex(1)?;
    dialog.SetDefaultExtension(default_extension)?;
    if !dialog.Show(owner)? {
        return Ok(None);
    }
    Ok(Some(
        dialog.GetResult()?.GetDisplayName(co::SIGDN::FILESYSPATH)?,
    ))
}
