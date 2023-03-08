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


SHM_NAME = "afl-btmin-shm"
SHM_SIZE = (1 << 16)

logging.basicConfig(level=logging.WARNING, format='[%(asctime)s] %(message)s')

if __name__ == "__main__":
    p = ArgumentParser("afl-btmin")
    p.add_argument("--afl", required=True, type=str, help="The AFL fuzzing output directory")
    p.add_argument("--filter", type=str, help="Filter for crashes")
    p.add_argument("--gdb", default=False, action="store_true", help="Enable gdb output")
    p.add_argument("--verbose", default=False, action="store_true", help="Verbose logging")
    p.add_argument("--top", default=3, type=int, help="Use top N frames to dedup")
    p.add_argument("--asan", type=str, help="ASAN binary for sanitizer crashes")

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

    if args.verbose:
        logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', force=True)

    remove_shm_from_resource_tracker()
    shm = SharedMemory(name=SHM_NAME, create=True, size=SHM_SIZE)
    try:
        bts: Mapping[Tuple, List[str]]  = {}

        for fname in os.listdir(Path(args.afl) / "crashes"):
            crash_fname = Path(args.afl) / "crashes" / fname

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

                if not "+san" in crash_fname.name:
                    # Write some value to verify it's us
                    shm.buf[:8] = struct.pack("<Q", 114514)

                    # -ex "set confirm off" -ex "set pagination off" -ex "r" -ex "bt" -ex "q"
                    gdb_args = [
                        "gdb"
                    ]

                    if use_stin:
                        run_args = ["-ex", f"r < {str(crash_fname.absolute())}"]
                    else:
                        run_args = ["ex", "r"]

                    gdb_args += [
                        "-ex", "set confirm off",
                        "-ex", "set pagination off",
                        "-ex", f"set backtrace limit {int(args.top) + 25}"] + run_args + [
                        "-ex", "bt",
                        "-ex", "q"
                    ]
                    

                    gdb_args += [
                        "--args"
                    ] + actual_args

                    if args.gdb:
                        subprocess.check_call(gdb_args)
                    else:
                        subprocess.check_call(gdb_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    try:
                        cnt = struct.unpack("<Q", shm.buf[:8])[0]
                        backtrace = pickle.loads(shm.buf[8:8+cnt])
                    except pickle.UnpicklingError as e:
                        logging.exception(f"Fail to get backtrace for {fname}, check your gdb settings")
                        continue
                    
                    n_frame = int(args.top)
                    backtrace = backtrace[:n_frame]
                else:
                    actual_args[0] = args.asan
                    backtrace = []
                    
                    if use_stin:
                        with open(crash_fname, "rb+") as f:
                            proc = subprocess.run(actual_args, stdin=f, stderr=subprocess.PIPE)
                    else:
                        proc = subprocess.run(actual_args, stderr=subprocess.PIPE)
                    
                    output = proc.stderr.decode("utf-8")
                    lns = output.split("\n")

                    in_error = False
                    for ln in lns:
                        if "ERROR" in ln:
                            in_error = True

                        if in_error:
                            tks = re.findall(r"#(\d+) [0-9xabcdef]+ in (.+) (.+)", ln.strip())

                            if len(tks) != 3:
                                if len(backtrace) != 0:
                                    in_error = False
                                continue

                            cur_level = int(tks[0])
                            ln_tks = tks[2].split(":")
                            if len(ln_tks) > 1:
                                ln_num = int(ln_tks[1])
                                src = ln_tks[0]
                            else:
                                ln_num = 0
                                src = ln_tks[0]

                            if cur_level >= args.top:
                                break
                            else:
                                backtrace.append((tks[1], src, ln_num))

                backtrace = tuple(backtrace)
                logging.info(f"Stack trace {fname}: {backtrace}")
                if backtrace not in bts:
                    bts[backtrace] = []
                bts[backtrace].append(fname)
        
        sys.stderr.write(f"{len(bts)} unique backtrace found\n")

        bt_dir = Path(args.afl) / "crashes" / "backtraces"
        os.makedirs(bt_dir, exist_ok=True)
        bt_id = 0
        for bt, fnames in bts.items():
            with open(bt_dir / f"{str(bt_id)}.json", "w+") as f:
                json.dump(bt, f, indent=4)

            for fname in fnames:
                suffix = Path(fname).suffix
                new_fname = ",".join([tk for tk in fname.split(",") if 'bt' not in tk])
                shutil.move(Path(args.afl) / "crashes" / fname, Path(args.afl) / "crashes" / f"{new_fname},bt:{bt_id}{suffix}")
            
            bt_id += 1
        
    finally:
        shm.close()
        shm.unlink()
