"""GUI automation: synthetic input (mouse, keyboard, window focus) via SendInput.

The model can now drive a target's interface directly: open the license dialog, click
Activate, paste a key. Everything goes through the native SendInput, so apps that
ignore WM_CHAR and PostMessage receive it like real user input.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import time
from typing import Any

_USER32 = ctypes.WinDLL("user32", use_last_error=True)
_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)


class _RECT(ctypes.Structure):
    _fields_ = [("left", wt.LONG), ("top", wt.LONG), ("right", wt.LONG), ("bottom", wt.LONG)]


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wt.LONG), ("dy", wt.LONG), ("mouseData", wt.DWORD), ("dwFlags", wt.DWORD),
                ("time", wt.DWORD), ("dwExtraInfo", ctypes.POINTER(wt.ULONG))]


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD), ("time", wt.DWORD),
                ("dwExtraInfo", ctypes.POINTER(wt.ULONG))]


class _INPUT(ctypes.Union):
    _fields_ = [("type", wt.DWORD), ("mi", _MOUSEINPUT), ("ki", _KEYBDINPUT)]


_INPUT_MOUSE = 0
_INPUT_KEYBOARD = 1
_KEYEVENTF_UNICODE = 0x0004
_KEYEVENTF_KEYUP = 0x0002
_MOUSEEVENTF_ABSOLUTE = 0x8000
_MOUSEEVENTF_MOVE = 0x0001
_MOUSEEVENTF_LEFTDOWN = 0x0002
_MOUSEEVENTF_LEFTUP = 0x0004


def _init_winapi() -> None:
    user32 = _USER32
    user32.FindWindowW.argtypes = [wt.LPCWSTR, wt.LPCWSTR]
    user32.FindWindowW.restype = wt.HWND
    user32.SetForegroundWindow.argtypes = [wt.HWND]
    user32.SetForegroundWindow.restype = wt.BOOL
    user32.GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(_RECT)]
    user32.GetWindowRect.restype = wt.BOOL
    user32.SendInput.argtypes = [wt.UINT, ctypes.POINTER(_INPUT), ctypes.c_int]
    user32.SendInput.restype = wt.UINT
    user32.GetForegroundWindow.restype = wt.HWND
    user32.GetCursorPos.argtypes = [ctypes.POINTER(wt.POINT)]
    user32.SetCursorPos.argtypes = [wt.INT, wt.INT]
    user32.SetCursorPos.restype = wt.BOOL
    user32.ShowWindow.argtypes = [wt.HWND, ctypes.c_int]
    user32.ShowWindow.restype = wt.BOOL
    user32.GetSystemMetrics.argtypes = [ctypes.c_int]
    user32.GetSystemMetrics.restype = ctypes.c_int


_init_winapi()


def _send_input(*inputs: _INPUT) -> int:
    array = (_INPUT * len(inputs))(*inputs)
    return _USER32.SendInput(len(inputs), array, ctypes.sizeof(_INPUT))


def _virtual_screen() -> tuple[int, int]:
    width = _USER32.GetSystemMetrics(0)
    height = _USER32.GetSystemMetrics(1)
    return width, height


def _absolute(x: int, y: int) -> tuple[int, int]:
    width, height = _virtual_screen()
    return int(x * 65535 / max(1, width - 1)), int(y * 65535 / max(1, height - 1))


def click(x: int, y: int, *, right: bool = False, double: bool = False) -> dict[str, Any]:
    """Move the mouse to screen coordinates and click (left/right, single/double)."""
    ax, ay = _absolute(x, y)
    _USER32.SetCursorPos(x, y)
    time.sleep(0.02)
    flags_down = _MOUSEEVENTF_ABSOLUTE | _MOUSEEVENTF_MOVE | (_MOUSEEVENTF_RIGHTDOWN if right else _MOUSEEVENTF_LEFTDOWN)
    flags_up = flags_down ^ (_MOUSEEVENTF_RIGHTDOWN if right else _MOUSEEVENTF_LEFTDOWN) | (_MOUSEEVENTF_RIGHTUP if right else _MOUSEEVENTF_LEFTUP)
    move = _INPUT(_INPUT_MOUSE); move.mi = _MOUSEINPUT(ax, ay, 0, _MOUSEEVENTF_ABSOLUTE | _MOUSEEVENTF_MOVE, 0, None)
    down = _INPUT(_INPUT_MOUSE); down.mi = _MOUSEINPUT(0, 0, 0, flags_down, 0, None)
    up = _INPUT(_INPUT_MOUSE); up.mi = _MOUSEINPUT(0, 0, 0, flags_up, 0, None)
    sent = _send_input(move, down, up)
    if double:
        down2 = _INPUT(_INPUT_MOUSE); down2.mi = _MOUSEINPUT(0, 0, 0, flags_down, 0, None)
        up2 = _INPUT(_INPUT_MOUSE); up2.mi = _MOUSEINPUT(0, 0, 0, flags_up, 0, None)
        _send_input(down2, up2)
    return {"clicked": sent == 3 or sent == 1, "x": x, "y": y, "right": right, "double": double}


def type_text(text: str, *, interval: float = 0.01) -> dict[str, list | int]:
    """Type unicode text through the keyboard stack (any window with focus receives it)."""
    for character in text:
        codes = [ord(character)]
        inputs = []
        for code in codes:
            down = _INPUT(_INPUT_KEYBOARD); down.ki = _KEYBDINPUT(0, code, _KEYEVENTF_UNICODE, 0, None)
            up = _INPUT(_INPUT_KEYBOARD); up.ki = _KEYBDINPUT(0, code, _KEYEVENTF_UNICODE | _KEYEVENTF_KEYUP, 0, None)
            inputs += [down, up]
        _send_input(*inputs)
        time.sleep(interval)
    return {"typed": len(text)}


def press_key(key: str, *, times: int = 1) -> dict[str, Any]:
    """Press a named key: enter, tab, esc, space, arrows, f1-f12, ctrl+a combinations.

    Names map to virtual-key codes; combos use ``ctrl+s`` / ``ctrl+shift+esc`` form.
    """
    vk_map = {
        "enter": 0x0D, "tab": 0x09, "esc": 0x1B, "escape": 0x1B, "space": 0x20,
        "backspace": 0x08, "delete": 0x2E, "del": 0x2E, "insert": 0x2D,
        "home": 0x24, "end": 0x23, "pageup": 0x21, "pagedown": 0x22,
        "left": 0x25, "up": 0x26, "right": 0x27, "down": 0x28,
        "f1": 0x70, "f2": 0x71, "f3": 0x72, "f4": 0x73, "f5": 0x74, "f6": 0x75,
        "f7": 0x76, "f8": 0x77, "f9": 0x78, "f10": 0x79, "f11": 0x7A, "f12": 0x7B,
        "ctrl": 0x11, "alt": 0x12, "shift": 0x10, "win": 0x5B,
        "a": 0x41, "c": 0x43, "v": 0x56, "x": 0x58, "s": 0x53, "z": 0x5A,
    }
    modifiers = []
    sequence = key.lower().replace(" ", "").split("+")
    keys = []
    for name in sequence:
        if name not in vk_map:
            return {"error": f"unknown key {name!r}; known: {sorted(vk_map)}"}
        keys.append(vk_map[name])
    for name in sequence[:-1]:
        if name in ("ctrl", "alt", "shift", "win"):
            modifiers.append(vk_map[name])
    inputs = []
    for vk in modifiers:
        down = _INPUT(_INPUT_KEYBOARD); down.ki = _KEYBDINPUT(vk, 0, 0, 0, None)
        inputs.append(down)
    main = keys[-1]
    for _ in range(max(1, times)):
        down = _INPUT(_INPUT_KEYBOARD); down.ki = _KEYBDINPUT(main, 0, 0, 0, None)
        up = _INPUT(_INPUT_KEYBOARD); up.ki = _KEYBDINPUT(main, 0, _KEYEVENTF_KEYUP, 0, None)
        inputs += [down, up]
    for vk in reversed(modifiers):
        up = _INPUT(_INPUT_KEYBOARD); up.ki = _KEYBDINPUT(vk, 0, _KEYEVENTF_KEYUP, 0, None)
        inputs.append(up)
    sent = _send_input(*inputs)
    return {"pressed": sent > 0, "key": key, "times": times}


def focus_window(title_or_class: str) -> dict[str, Any]:
    """Bring a window (by exact title or class name) to the foreground."""
    hwnd = _USER32.FindWindowW(None, title_or_class)
    if not hwnd:
        hwnd = _USER32.FindWindowW(title_or_class, None)
    if not hwnd:
        return {"error": f"no top-level window titled-or-classed {title_or_class!r}; check window_list"}
    _USER32.ShowWindow(hwnd, 9)  # SW_RESTORE
    time.sleep(0.05)
    ok = _USER32.SetForegroundWindow(hwnd)
    time.sleep(0.1)
    foreground = _USER32.GetForegroundWindow()
    return {"focused": bool(ok and foreground == hwnd), "hwnd": hex(hwnd)}


def window_rect(title_or_class: str) -> dict[str, Any]:
    """Screen rectangle of a window - the coordinates for click() inside it."""
    hwnd = _USER32.FindWindowW(None, title_or_class)
    if not hwnd:
        hwnd = _USER32.FindWindowW(title_or_class, None)
    if not hwnd:
        return {"error": f"window {title_or_class!r} not found"}
    rect = _RECT()
    if not _USER32.GetWindowRect(hwnd, ctypes.byref(rect)):
        return {"error": "GetWindowRect failed"}
    return {"left": rect.left, "top": rect.top, "right": rect.right, "bottom": rect.bottom,
            "width": rect.right - rect.left, "height": rect.bottom - rect.top}
