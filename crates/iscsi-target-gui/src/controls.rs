//! WinSafe control을 다룰 때 되풀이되는 작은 도우미.

use winsafe::{self as w, co, gui};

/// Edit의 글자를 읽는다.
///
/// 글자가 없으면 `GetWindowTextLength`는 0을 돌려주고, WinSafe는 그것이 오류인지
/// 가리려고 thread의 마지막 오류 코드를 본다. 그 코드는 앞선 다른 호출이 남긴 것일 수
/// 있어서, 비어 있는 칸을 읽다가 엉뚱한 오류가 난다. 읽기 전에 코드를 지운다.
pub fn text(edit: &gui::Edit) -> w::SysResult<String> {
    w::SetLastError(co::ERROR::SUCCESS);
    edit.text()
}

/// 창의 글자 수. [`text`]와 같은 이유로 마지막 오류 코드를 먼저 지운다.
pub fn text_length(hwnd: &w::HWND) -> w::SysResult<i32> {
    w::SetLastError(co::ERROR::SUCCESS);
    hwnd.GetWindowTextLength()
}
