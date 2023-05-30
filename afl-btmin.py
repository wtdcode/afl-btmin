#!/usr/bin/python3

from argparse import ArgumentParser
from pathlib import Path
from multiprocessing.shared_memory import SharedMemory
from typing import Mapping, Tuple, List
from multiprocessing import resource_tracker
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

# Workaround found at https://stackoverflow.com/questions/64102502/shared-memory-deleted-at-exit
# for https://bugs.python.org/issue39959
def remove_shm_from_resource_tracker():
    """Monkey-patch multiprocessing.resource_tracker so SharedMemory won't be tracked

    More details at: https://bugs.python.org/issue38119
    """

    def fix_register(name, rtype):
        if rtype == "shared_memory":
            return
        return resource_tracker._resource_tracker.register(name, rtype)
    resource_tracker.register = fix_register

    def fix_unregister(name, rtype):
        if rtype == "shared_memory":
            return
        return resource_tracker._resource_tracker.unregister(name, rtype)
    resource_tracker.unregister = fix_unregister

    if "shared_memory" in resource_tracker._CLEANUP_FUNCS:
        del resource_tracker._CLEANUP_FUNCS["shared_memory"]


# SHM_NAME = "afl-btmin-shm"
SHM_SIZE = (1 << 16)

logging.basicConfig(level=logging.WARNING, format='[%(asctime)s] %(message)s')


def get_by_gdb(args: List[str], shm: SharedMemory, verbose: bool, use_stdin: bool, repeat: int, timeout: int, shm_name: str):
    meta = {
        "lines": []
    }
    for _ in range(repeat):
        shm.buf[:8] = struct.pack("<Q", 114514)

        # -ex "set confirm off" -ex "set pagination off" -ex "r" -ex "bt" -ex "q"
        gdb_args = [
            "gdb"
        ]

        if use_stin:
            run_args = ["-ex", f"r < {str(crash_fname.absolute())}"]
        else:
            run_args = ["-ex", "r"]

        gdb_args += [
            "-ex", "set confirm off",
            "-ex", "set pagination off",
            "-ex", f"set backtrace limit 10"] + run_args + [
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
            logging.info(f"Fail to get backtrace for {fname} using gdb, this could be fine")
            return None
        finally:
            shm.buf[:SHM_SIZE] = b'\x00' * SHM_SIZE
        
        if len(backtrace) != 0:
            return backtrace
    
    return None

def get_by_asan(args: List[str], verbose: bool, use_stdin: bool, repeat: int, timeout: int):
    envs = os.environ.copy()
    if "ASAN_OPTIONS" not in envs:
        envs["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0:print_stacktrace=1"
    if "MSAN_OPTIONS" not in envs:
        envs["MSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    if "UBSAN_OPTIONS" not in envs:
        envs["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
    meta = {
        "lines": [],
        "regions": []
    }
    for _ in range(repeat):
        
        try:
            if use_stdin:
                with open(crash_fname, "rb+") as f:
                    proc = subprocess.run(args, stdin=f, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=envs)
            else:
                proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=envs)
        except subprocess.TimeoutExpired:
            logging.warning("Timeout waiting for sanitizers, retry...")
            continue
        
        raw_stderr = proc.stderr       
        output = raw_stderr
        lns = output.split(b"\n")

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
                ln = ln.decode("utf-8")
                if "BuildId" in ln:
                    ln = " ".join(ln.strip().split(" ")[:-2])
                tks = re.findall(r"#(\d+) [0-9xabcdef]+ in (.+) (.+)", ln)

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
                ln_tks = tks[2].split(":")
                if len(ln_tks) > 1:
                    ln_num = int(ln_tks[1])
                    src = Path(ln_tks[0]).name
                    if Path(ln_tks[0]).exists():
                        try:
                            fcontent = open(ln_tks[0]).read().split("\n")
                        except Exception:
                            lncontent = f"Fail to load {ln_tks[0]}:{ln_num}"
                        else:
                            lncontent = fcontent[ln_num - 1]
                    else:
                        lncontent = "<No available source>"
                else: 
                    path_tks = re.findall(r"\((.*)\+([0-9xabcdef]+)\)", tks[2])
                    ln_num = 0
                    if len(path_tks) == 1 and len(path_tks[0]) == 2:
                        src_path, offset = path_tks[0]
                        src = f"{Path(src_path).name}+{offset}"
                        lncontent = "<No available source>"
                    else:
                        src = Path(ln_tks[0]).name
                        if Path(ln_tks[0]).exists():
                            try:
                                fcontent = open(ln_tks[0]).read().split("\n")
                            except Exception:
                                lncontent = f"Fail to load {ln_tks[0]}:{ln_num}"
                            else:
                                lncontent = fcontent[ln_num - 1]
                        else:
                            lncontent = "<No available source>"
                if in_error:
                    backtrace.append((tks[1], src, ln_num))
                    meta["lines"].append(lncontent)
                else:
                    region_trace.append((tks[1], src, ln_num))

        if len(return_backtrace) != 0:
            return return_backtrace, meta

    return None, None

if __name__ == "__main__":
    p = ArgumentParser("afl-btmin")
    p.add_argument("--input", required=True, type=str, help="The AFL fuzzing output directory")
    p.add_argument("--filter", type=str, help="Filter for crashes")
    p.add_argument("--verbose", default=False, action="store_true", help="Verbose logging")
    p.add_argument("--top", default=3, type=int, help="Use top N frames to dedup")
    p.add_argument("--asan", type=str, help="ASAN binary for sanitizer crashes")
    p.add_argument("--msan", type=str, help="MSAN binary for sanitizer crashes")
    p.add_argument("--ubsan", type=str, help="UBSAN binary (can be recovered!)")
    p.add_argument("--timeout", type=int, default=5, help="Timeout for a single run")
    p.add_argument("--repeat", type=int, default=5, help="Repeat execution in case the crash is not stable")
    p.add_argument("--no-gdb", default=False, action="store_true", help="No gdb")
    p.add_argument("--meta", default=False, action="store_true", help="Store extra meta")
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
    if len(seq) != 3 or not ("a" in seq and "u" in seq and "m" in seq):
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
        remove_shm_from_resource_tracker()
        shm_name = f"afl-btmin-{os.getpid()}"
        shm = SharedMemory(name=shm_name, create=True, size=SHM_SIZE)
    try:
        bts: Mapping[Tuple, List[str]]  = {}
        metas: Mapping[Tuple, dict] = {}
        cnt = 0

        for fname in os.listdir(Path(args.input)):
            crash_fname = Path(args.input) / fname
            cnt += 1
            
            if cnt % 100 == 0:
                sys.stderr.write(f"mimizing {cnt}th output from {args.input}...\n")

            if crash_fname.is_file() and "id:" in fname:
                
                if args.filter is not None:
                    if re.match(args.filter, fname) is None:
                        logging.warning(f"{fname} is skipped")
                        continue
                    
                actual_args = []
                use_stin = "@@" not in program_args
                for arg in program_args:
                    if arg == "@@":
                        actual_args.append(str(crash_fname.absolute()))
                    else:
                        actual_args.append(arg)

                san_only_crash = False
                backtrace = None
                for san in sans:
                    if san is not None:
                        actual_args[0] = san
                        backtrace, meta = get_by_asan(actual_args, args.verbose, use_stin, repeat, args.timeout)
                        if backtrace is not None:
                            logging.info(f"Got backtrace {backtrace} from {san}")
                            san_only_crash = True
                            if san == args.ubsan:
                                backtrace = backtrace[:1]
                                if meta is not None:
                                    meta['san'] = san
                            break       

                if not args.no_gdb:
                    actual_args[0] = program_args[0]
                    gdb_bt = get_by_gdb(actual_args, shm, args.verbose, use_stin, repeat, args.timeout, shm_name)
                    if gdb_bt is not None:
                        san_only_crash = False
                        if backtrace is None:
                            backtrace = gdb_bt
                
                if backtrace is None or len(backtrace) == 0:
                    logging.warning(f"Fail to get backtrace for {crash_fname}, skipped")
                    continue
                    
                n_frame = int(args.top)
                backtrace = tuple(backtrace[:n_frame])
                logging.info(f"Stack trace {fname}: {backtrace}")
                if backtrace not in bts:
                    bts[backtrace] = []
                bts[backtrace].append((fname, san_only_crash))
                metas[backtrace] = meta

        # check if all backtraces are of the same length
        min_length = int(args.top)
        for bt in bts.keys():
            if len(bt) < min_length:
                min_length = len(bt)
        
        new_bts = {}
        new_meta = {}
        for bt, names in bts.items():
            new_bt = bt[:min_length]
            if new_bt not in new_bts:
                new_bts[new_bt] = []
            new_bts[new_bt].extend(names)
            new_meta[new_bt] = metas[bt]
        
        bts = new_bts
        metas = new_meta
        
        sys.stderr.write(f"{len(bts)} unique backtrace found\n")

        bt_dir = Path(args.input) / "backtraces"
        shutil.rmtree(bt_dir, ignore_errors=True)
        os.makedirs(bt_dir, exist_ok=True)
        bt_id = 0
        for bt, fnames in bts.items():
            with open(bt_dir / f"{str(bt_id)}.json", "w+") as f:
                json.dump(bt, f, indent=4)

            if args.meta:
                with open(bt_dir / f"{str(bt_id)}.json.meta", "w+") as f:
                    json.dump(new_meta[bt], f, indent=4)
            
            for fname, san_only in fnames:
                suffix = Path(fname).suffix
                stem = Path(fname).stem
                new_fname = ",".join([tk for tk in stem.split(",") if 'bt' not in tk and 'sanonly' not in tk])
                if san_only:
                    n = f"{new_fname},+sanonly,bt:{bt_id}{suffix}"
                else:
                    n = f"{new_fname},bt:{bt_id}{suffix}"
                shutil.move(Path(args.input) / fname, Path(args.input) / n)
            
            bt_id += 1
        
    finally:
        if not args.no_gdb:
            shm.close()
            shm.unlink()
