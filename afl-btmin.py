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

SHM_NAME = "afl-btmin-shm"
SHM_SIZE = (1 << 16)

if __name__ == "__main__":
    p = ArgumentParser("afl-btmin")
    p.add_argument("--output", required=True, type=str, help="The AFL output directory")
    p.add_argument("--filter", type=str, help="Filter for crashes")    

    program_args = None
    our_args = None
    for idx, arg in enumerate(sys.argv):
        if arg == "--":
            our_args = sys.argv[0:idx]
            program_args = sys.argv[idx+1:]

    if our_args is None:
        sys.stderr.write("No program arguments are given!\n")
        exit(-1)

    args = p.parse_args(our_args)
    shm = SharedMemory(name=SHM_NAME, size=SHM_SIZE)

    bts: Mapping[Tuple, List[str]]  = {}

    for fname in os.listdir(Path(args.output) / "crashes"):
        crash_fname = Path(args.output) / "crashes" / fname

        if crash_fname.is_file():
            
            if args.filter is not None:
                if re.match(args.filter, fname) is None:
                    print(f"{fname} is skipped")
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

            subprocess.check_call(gdb_args)

            cnt = struct.unpack("<Q", shm.buf[:8])[0]
            backtrace = pickle.loads(shm.buf[8:8+cnt])

            if backtrace not in bts:
                bts[backtrace] = []
            else:
                bts[backtrace].append(fname)
    
    print(f"{len(bts)} unique backtrace found")
