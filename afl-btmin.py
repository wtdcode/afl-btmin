#!/usr/bin/python3

from argparse import ArgumentParser
from pathlib import Path
from multiprocessing import resource_tracker as _mprt
from multiprocessing import shared_memory as _mpshm
from multiprocessing.shared_memory import SharedMemory
from typing import Mapping, Tuple, List, Optional
import threading
import subprocess
import sys
import struct
import os
import pickle
import re
import logging
import json
import shutil
import os

# Copy Paste from https://github.com/python/cpython/issues/82300#issuecomment-2692889533
if sys.version_info >= (3, 13):
    SharedMemory = _mpshm.SharedMemory
else:
    class SharedMemory(_mpshm.SharedMemory):
        __lock = threading.Lock()

        def __init__(
            self, name: str | None = None, create: bool = False,
            size: int = 0, *, track: bool = True
        ) -> None:
            self._track = track

            # if tracking, normal init will suffice
            if track:
                return super().__init__(name=name, create=create, size=size)

            # lock so that other threads don't attempt to use the
            # register function during this time
            with self.__lock:
                # temporarily disable registration during initialization
                orig_register = _mprt.register
                _mprt.register = self.__tmp_register

                # initialize; ensure original register function is
                # re-instated
                try:
                    super().__init__(name=name, create=create, size=size)
                finally:
                    _mprt.register = orig_register

        @staticmethod
        def __tmp_register(*args, **kwargs) -> None:
            return

        def unlink(self) -> None:
            if _mpshm._USE_POSIX and self._name:
                _mpshm._posixshmem.shm_unlink(self._name)
                if self._track:
                    _mprt.unregister(self._name, "shared_memory")


# SHM_NAME = "afl-btmin-shm"
SHM_SIZE = (1 << 16)

logging.basicConfig(level=logging.WARNING, format='[%(asctime)s] %(message)s')


def get_by_gdb(args: List[str], shm: SharedMemory, verbose: bool, use_stdin: Optional[str], repeat: int, timeout: int, shm_name: str):
    for _ in range(repeat):
        shm.buf[:8] = struct.pack("<Q", 114514)

        # -ex "set confirm off" -ex "set pagination off" -ex "r" -ex "bt" -ex "q"
        gdb_args = [
            "gdb"
        ]

        if use_stdin is not None:
            run_args = ["-ex", f"r < {str(Path(use_stdin).absolute())}"]
        else:
            run_args = ["-ex", "r"]

        gdb_args += [
            "-ex", "set confirm off",
            "-ex", "set pagination off",
            "-ex", f"set backtrace limit 32"] + run_args + [
            "-ex", "bt",
            "-ex", "q"
        ]
        

        gdb_args += [
            "--args"
        ] + args
        env = os.environ.copy()
        env["AFL_BTMIN_SHM"] = shm_name
        if "ASAN_OPTIONS" not in env:
            env["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0:print_stacktrace=1"
        if "MSAN_OPTIONS" not in env:
            env["MSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1:max_allocation_size_mb=2047:allocator_may_return_null=false" # We are at gdb, let it break early
        if "UBSAN_OPTIONS" not in env:
            env["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
        try:
            if verbose:
                logging.info(f"gdb_args: {' '.join(gdb_args)}")
                subprocess.check_call(gdb_args, timeout=timeout, env=env)
            else:
                subprocess.check_call(gdb_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            logging.warning(f"Timeout waiting for gdb: {gdb_args}, retry...")
            continue
        except Exception as e:
            logging.exception("Getting exception, simply retry...")
            continue
        try:
            cnt = struct.unpack("<Q", shm.buf[:8])[0]
            backtrace = pickle.loads(shm.buf[8:8+cnt])
        except pickle.UnpicklingError as e:
            logging.info(f"Fail to get backtrace for {use_stdin} using gdb, this could be fine")
            return None
        finally:
            shm.buf[:SHM_SIZE] = b'\x00' * SHM_SIZE
        
        if len(backtrace) != 0:
            return backtrace
    
    return None

def get_by_asan(args: List[str], verbose: bool, use_stdin: Optional[str], repeat: int, timeout: int):
    envs = os.environ.copy()
    if "ASAN_OPTIONS" not in envs:
        envs["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0:print_stacktrace=1"
    if "MSAN_OPTIONS" not in envs:
        envs["MSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    if "UBSAN_OPTIONS" not in envs:
        envs["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    meta = {
        "lines": [],
        "regions": [],
        "out_san": []
    }
    for _ in range(repeat):
        
        try:
            if use_stdin is not None:
                with open(use_stdin, "rb+") as f:
                    proc = subprocess.run(args, stdin=f, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=envs)
            else:
                proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=envs)
        except subprocess.TimeoutExpired:
            logging.warning("Timeout waiting for sanitizers, retry...")
            continue
        
        raw_stderr = proc.stderr       
        output = raw_stderr
        lns = output.split(b"\n")
        
        if b"UndefinedBehaviorSanitizer" in output:
            meta['out_san'].append("ubsan")
        elif b"MemorySanitizer" in output:
            meta['out_san'].append("msan")
        elif b"AddressSanitizer" in output:
            meta['out_san'].append("asan")

        logging.info(f"ASAN stderr: {output}")
        in_error = False
        in_located = False
        backtrace = []
        region_trace = []
        return_backtrace = []
        for ln in lns:
            if b"ERROR" in ln or b"WARNING" in ln or b"runtime error" in ln:
                in_error = True

            if b"is located" in ln:
                in_located = True
                
            if in_error or in_located:
                try:
                    ln = ln.decode("utf-8")
                except UnicodeDecodeError as e:
                    print(f"Decode failure {str(e)} for line: {ln}")
                    continue
                if "BuildId" in ln:
                    ln = " ".join(ln.strip().split(" ")[:-2])
                tks = re.findall(r"#(\d+) ([0-9xabcdef]+) in (.+) (.+)", ln)

                if len(tks) == 0:
                    if len(backtrace) != 0 and in_error:
                        return_backtrace = backtrace
                        in_error = False
                    if len(region_trace) != 0 and in_located:
                        in_located = False
                        meta["regions"].append(region_trace)
                        region_trace = []
                    continue
                tks = tks[0]
                ln_tks = tks[3].split(":")
                if len(ln_tks) > 1:
                    ln_num = int(ln_tks[1])
                    if Path(ln_tks[0]).exists():
                        src = str(Path(ln_tks[0]).absolute())
                    else:
                        src = ln_tks[0] # ??
                else: 
                    ln_num = None
                    src = ln_tks[0]
                if in_error:
                    backtrace.append((tks[1], tks[2], src, ln_num))
                else:
                    region_trace.append((tks[1], tks[2], src, ln_num))

        if len(return_backtrace) != 0:
            return return_backtrace, meta

    return None, None

if __name__ == "__main__":
    p = ArgumentParser("afl-btmin")
    p.add_argument("--verbose", default=False, action="store_true", help="Verbose logging")
    p.add_argument("--top", default=10, type=int, help="Use top N frames to dedup")
    p.add_argument("--asan", type=str, help="ASAN binary for sanitizer crashes")
    p.add_argument("--msan", type=str, help="MSAN binary for sanitizer crashes")
    p.add_argument("--ubsan", type=str, help="UBSAN binary (can be recovered!)")
    p.add_argument("--timeout", type=int, default=5, help="Timeout for a single run")
    p.add_argument("--repeat", type=int, default=5, help="Repeat execution in case the crash is not stable")
    p.add_argument("--no-gdb", default=False, action="store_true", help="No gdb")
    p.add_argument("--stdin", type=str, help="use stdin")
    p.add_argument("--sequence", type=str, default="uam", help="sequence of the sanitizers")

    program_args = None
    our_args = None
    for idx, arg in enumerate(sys.argv):
        if arg == "--":
            our_args = sys.argv[0:idx]
            program_args = sys.argv[idx+1:]

    if our_args is None and "-h" not in sys.argv and "--help" not in sys.argv:
        sys.stderr.write("No program arguments are given!\n")
        exit(-1)

    if our_args is None:
        our_args = sys.argv

    args = p.parse_args(our_args[1:])

    seq = args.sequence
    if not ("a" in seq or "u" in seq or "m" in seq):
        sys.stderr.write("sequence should be like uam, where u-ubsan a-asan m-msan")
        exit(-1)
        
    seq_mapping = {
        "a": args.asan,
        "u": args.ubsan,
        "m": args.msan
    }
    
    sans = [seq_mapping[s] for s in seq]
    
    repeat = int(args.repeat)
    if args.verbose:
        logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', force=True)

    if not args.no_gdb:
        shm_name = f"afl-btmin-{os.getpid()}"
        shm = SharedMemory(name=shm_name, create=True, size=SHM_SIZE)
    try:
        actual_args = program_args[:]
        san_only_crash = False
        backtrace = None
        meta = None
        for san in sans:
            if san is not None:
                actual_args[0] = san
                backtrace, meta = get_by_asan(actual_args, args.verbose, args.stdin, repeat, args.timeout)
                if backtrace is not None:
                    logging.info(f"Got backtrace {backtrace} from {san}")
                    # if meta is not None and "out_san" in meta and "ubsan" in meta['out_san']:
                    #     backtrace = backtrace[:1]
                    if meta is not None:
                        meta['san'] = san
                    break       

        if backtrace is None and not args.no_gdb:
            actual_args[0] = program_args[0]
            gdb_bt = get_by_gdb(actual_args, shm, args.verbose, args.stdin, repeat, args.timeout, shm_name)
            if gdb_bt is not None:
                backtrace = gdb_bt
            
        n_frame = int(args.top)
        backtrace = tuple(backtrace[:n_frame])

        out = {
            "backtraces": [{
                "pc": bt[0],
                "function": bt[1],
                "source": bt[2],
                "line": bt[3]
            } for bt in backtrace],
            "meta": meta
        }
        print(json.dumps(out, indent=2))
    finally:
        if not args.no_gdb:
            shm.close()
            shm.unlink()
