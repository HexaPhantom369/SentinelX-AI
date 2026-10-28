import re
from pathlib import PureWindowsPath


PROTECTED_PROCESS_NAMES = {
    "csrss", "lsass", "services", "smss", "system", "system idle process",
    "wininit", "winlogon", "svchost", "registry", "secure system",
}


def canonical_process_id(value):
    if not isinstance(value, str):
        return None
    if re.fullmatch(r"0[xX][0-9a-fA-F]{1,8}", value):
        pid = int(value, 16)
    elif value.isdecimal():
        pid = int(value, 10)
    else:
        return None
    if pid <= 4 or pid > 2_147_483_647:
        return None
    return str(pid)


def eligible_process(process_id, process_name):
    pid = canonical_process_id(process_id)
    if pid is None or not isinstance(process_name, str):
        return None
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,255}", process_name):
        return None
    base_name = PureWindowsPath(process_name).stem.casefold()
    if base_name in PROTECTED_PROCESS_NAMES:
        return None
    return pid
