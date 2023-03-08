from gdb.FrameDecorator import FrameDecorator
import gdb
import pickle
import struct
import binascii
from typing import List
from itertools import tee
from multiprocessing.shared_memory import SharedMemory
from multiprocessing import resource_tracker
from pathlib import Path

SHM_NAME = "afl-btmin-shm"

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

def load_shm():
    remove_shm_from_resource_tracker()
    try:
        shm = SharedMemory(name=SHM_NAME, create=False)
        v = struct.unpack("<Q", shm.buf[:8])[0]
        if v != 114514:
            print("Fail to verfiy the shared memory")
            shm.close()
            return None
        return shm
    except Exception:
        print("Share memory doesn't exist!")
        return None

class FrameFilter():

    def __init__(self) -> None:
        self.name = "afl-btmin"
        self.priority = 100
        self.enabled = True
        gdb.frame_filters[self.name] = self

    def _gen_backtrace(self, frames: List[FrameDecorator]):
        backtraces = []

        for frame in frames:
            func = frame.function()

            if func == frame.inferior_frame().pc():
                # In this case, gdb fails to find a function boundary, it happens mostly for
                # libc subroutines in assembly files. It's fairly enough to use filenames and
                # line numbers to identify the backtrace in this case, so we assign a fake pc
                # to avoid generate different backtrace.
                func = "0x19260817"
            
            fname = frame.filename()

            # We have to add line numbers for functions (like overloaded) which shares the same name.
            ln = frame.line()

            if fname is not None:
                fname = "nosource"
            else:
                fname = Path(fname).name
            backtraces.append((func, fname, ln))
        
        return tuple(backtraces)

    def filter(self, it):
        shm = load_shm()
        if shm is not None:
            it1, it2 = tee(it)
            backtrace =  self._gen_backtrace(list(it2))
            bs = pickle.dumps(backtrace)
            shm.buf[:8] = struct.pack("<Q", len(bs))
            shm.buf[8:len(bs) + 8] = bs
            print(f"Wrote {len(bs) + 8} bytes: {binascii.hexlify(shm.buf[:16])}")
            shm.close()
            return it1
        else:
            print("Warning: no shared memory is detected")
            return it

FrameFilter()