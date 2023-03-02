from argparse import ArgumentParser
from pathlib import Path
from multiprocessing.shared_memory import SharedMemory
from typing import Mapping, Tuple, List
import subprocess
import sys
import struct
import os
import pickle
import re
import logging
import json
import shutil

SHM_NAME = "afl-btmin-shm"
SHM_SIZE = (1 << 16)

logging.basicConfig(level=logging.WARNING, format='[%(asctime)s] %(message)s')

if __name__ == "__main__":
    p = ArgumentParser("afl-btmin")
    p.add_argument("--afl", required=True, type=str, help="The AFL fuzzing output directory")
    p.add_argument("--output", required=True, type=str, help="The output directory")
    p.add_argument("--filter", type=str, help="Filter for crashes")
    p.add_argument("--gdb", default=False, action="store_true", help="Enable gdb output")
    p.add_argument("--verbose", default=False, action="store_true", help="Verbose logging")
    p.add_argument("--top", default=3, type=int, help="Use top N frames to dedup")

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

    shm = SharedMemory(name=SHM_NAME, create=True, size=SHM_SIZE)
    try:
        bts: Mapping[Tuple, List[str]]  = {}

        for fname in os.listdir(Path(args.afl) / "crashes"):
            crash_fname = Path(args.afl) / "crashes" / fname

            if crash_fname.is_file():
                
                if args.filter is not None:
                    if re.match(args.filter, fname) is None:
                        logging.warning(f"{fname} is skipped")
                        continue

                # Write some value to verify it's us
                shm.buf[:8] = struct.pack("<Q", 114514)

                # -ex "set confirm off" -ex "set pagination off" -ex "r" -ex "bt" -ex "q"
                gdb_args = [
                    "gdb"
                ]

                gdb_args += [
                    "-ex", "set confirm off",
                    "-ex", "set pagination off",
                    "-ex", "r",
                    "-ex", "bt",
                    "-ex", "q"
                ]

                actual_args = []

                for arg in program_args:
                    if arg == "@@":
                        actual_args.append(str(crash_fname.absolute()))
                    else:
                        actual_args.append(arg)

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
                logging.info(f"Stack trace {fname}: {backtrace}")
                if backtrace not in bts:
                    bts[backtrace] = []
                else:
                    bts[backtrace].append(fname)
        
        sys.stderr.write(f"{len(bts)} unique backtrace found\n")
        if not Path(args.output).exists():
            os.makedirs(args.output)
        
        for idx, bt in enumerate(bts.keys()):
            dir_path = Path(args.output) / str(idx)
            if dir_path.exists():
                logging.warning(f"{dir_path} already exists, content will be overwritten")
            else:
                os.makedirs(dir_path)
            with open(dir_path / "backtrace.json", "w+") as f:
                json.dump(bt, f, indent=4)
            
            for crash in bts[bt]:
                shutil.copy(Path(args.afl) / "crashes" / crash, dir_path / crash)
        
    finally:
        # shm.close()
        shm.unlink()
