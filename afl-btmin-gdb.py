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
from multiprocessing import resource_tracker as _mprt
from multiprocessing import shared_memory as _mpshm
import threading
import os
import sys


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

def load_shm():
    try:
        shm_name = os.getenv("AFL_BTMIN_SHM")
        if shm_name is None:
            return None
        shm = SharedMemory(name=shm_name, create=False, track=False)
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
        self.__debug = "BTMIN_DEBUG" in os.environ
        gdb.frame_filters[self.name] = self

    def _gen_backtrace(self, frames: List[FrameDecorator]):
        backtraces = []

        for frame in frames:
            if self.__debug:
                print(f"frame is {frame}")
            func = frame.function()
            fname = frame.filename()
            ln = frame.line()

            if fname is not None:
                if Path(fname).exists():
                    fname = str(Path(fname).absolute())
            address = frame.address()
            backtraces.append((address, func, fname, ln))
        
        return tuple(backtraces)

    def filter(self, it):
        shm = load_shm()
        if shm is not None or self.__debug:
            it1, it2 = tee(it)
            backtrace =  self._gen_backtrace(list(it2))
            if shm:
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