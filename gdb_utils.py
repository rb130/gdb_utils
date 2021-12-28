from typing import Union, Optional
import gdb
import json
import subprocess
import signal
import os
import re


debug = False


def delay_signal(pid: int, signal: Union[int, str], timeout: int):
    return subprocess.Popen([
        "/bin/sh", "-c",
        "sleep %d && kill -%s %d"
        % (timeout, signal, pid)
    ])


def gdb_execute(cmd: str, show: Optional[bool] = None):
    if show is None:
        show = debug
    if debug:
        print(cmd)
    return gdb.execute(cmd, from_tty=False, to_string=not show)


def gdb_execute_timeout(cmd: str, timeout: Optional[int] = None, show: Optional[bool] = None):
    if show is None:
        show = debug
    if timeout is None:
        gdb_execute(cmd, show)
        return
    #pid = os.getpid()
    pid = gdb.selected_inferior().pid
    proc = delay_signal(pid, int(signal.SIGINT), timeout)
    gdb_bad = None
    ans = None
    try:
        try:
            ans = gdb_execute(cmd, show)
        except gdb.error as e:
            gdb_bad = e
        if proc.poll() is not None:
            # program was killed
            raise KeyboardInterrupt
        else:
            # stop killer
            proc.kill()
            if gdb_bad:
                raise gdb_bad
            return ans
    except KeyboardInterrupt:
        raise TimeoutError("gdb execute timeout")


def kill_all():
    inferior_id = [i.num for i in gdb.inferiors()]
    if len(inferior_id) > 0:
        inferiors = " ".join(map(str, inferior_id))
        gdb_execute("kill inferiors " + inferiors)


def gdb_quit():
    kill_all()
    gdb_execute("quit")


def gdb_live() -> bool:
    return any(th.is_valid() for th in gdb.selected_inferior().threads())


def gdb_path(s: str) -> str:
    # auto add escape charactors and outer quotes
    s = json.dumps(s)
    s = s.replace("$", "\\$")
    return s


def read_reg(reg: str) -> int:
    return int(gdb.parse_and_eval("$" + reg))


def write_reg(reg: str, value: int):
    gdb_execute("set $%s = %d" % (reg, value))


def read_mem(address: int, size: int) -> bytes:
    inferior = gdb.selected_inferior()
    buf = inferior.read_memory(address, size)
    return bytes(buf)


def write_mem(address: int, buffer: bytes):
    inferior = gdb.selected_inferior()
    inferior.write_memory(address, buffer)


def gdb_load_address(bin_name: str) -> Optional[int]:
    bin_name = os.path.basename(bin_name)
    results = gdb_execute("info proc mappings", show=False)
    start = False
    addr_pattern = re.compile(r"(0x[0-9a-fA-F]+)\s+((0x)?[0-9a-fA-F]+\s+)+(.*)$")
    for line in results.split("\n"):
        if "Start Addr" in line:
            start = True
            continue
        if not start:
            continue
        line = line.strip()
        match = addr_pattern.match(line)
        if match is None:
            continue
        groups = match.groups()
        obj = groups[-1]
        if os.path.basename(obj) == bin_name:
            addr = int(groups[0], 16)
            return addr
    return None


def gdb_exit_code() -> Optional[int]:
    val = gdb.parse_and_eval("$_exitcode")
    if val.type.code == gdb.TYPE_CODE_VOID:
        return None
    return int(val)


def gdb_exit_signal() -> Optional[int]:
    val = gdb.parse_and_eval("$_exitsignal")
    if val.type.code == gdb.TYPE_CODE_VOID:
        return None
    return int(val)


def gdb_switch_thread(tid: int) -> bool:
    for t in gdb.selected_inferior().threads():
        if not t.is_valid():
            continue
        if t.global_num == tid:
            t.switch()
            return True
    return False
