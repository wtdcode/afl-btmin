from gdb.FrameDecorator import FrameDecorator
import gdb
import pickle
import struct
from itertools import tee
from multiprocessing.shared_memory import SharedMemory

SHM_NAME = "afl-btmin-shm"

def load_shm():
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
        gdb.frame_filters[self.name] = self

    def filter(self, it):
        shm = load_shm()
        if shm is not None:
            it1, it2 = tee(it)
            backtrace = tuple([(frame.function(), frame.filename(), frame.line()) for frame in it2])
            bs = pickle.dumps(backtrace)
            self.shm.buf[:8] = struct.pack("<Q", len(bs))
            self.shm.buf[8:len(bs) + 8] = bs
            return it1
        else:
            return it

FrameFilter()