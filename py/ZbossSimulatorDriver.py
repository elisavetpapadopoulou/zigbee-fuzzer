from threading import ExceptHookArgs, Lock
from typing import List, Tuple, Union
from scapy.all import RandByte, Tuple
from scapy.layers import dot15d4, zigbee
from scapy.layers.dot15d4 import Dot15d4, Dot15d4Beacon, Dot15d4Data, Dot15d4Cmd, Dot15d4Beacon
import os, time, selectors
dot15d4.conf.dot15d4_protocol = "zigbee"
dot15d4.conf.dot15d4_fcs = False


def _open_nonblock(path, flags):
    while True:
        try:
            return os.open(path, flags | os.O_NONBLOCK)
        except OSError:
            time.sleep(0.2)

def _read_exact(fd, n):
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = os.read(fd, n - len(buf))
            if not chunk:
                try:
                    os.close(fd)
                except OSError:
                    pass
                fd = _open_nonblock(RPIPE, os.O_RDONLY)
                continue
            buf += chunk
        except BlockingIOError:
            time.sleep(0.01)
    return bytes(buf)

class ZbossSimulatorDriver:
    def __init__(self, rpipe, wpipe):
        self.fd_w = os.open(wpipe, os.O_WRONLY)
        self.wpipe = wpipe
        self.rpipe = rpipe
        self.fd_r = _open_nonblock(rpipe, os.O_RDONLY)
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.fd_r, selectors.EVENT_READ)
        self._wlock = Lock()
        self.closed = False

    def _reopen_r(self):
        try:
            self.fd_w = os.open(self.wpipe, os.O_WRONLY)
        except OSError as e:
            raise ConnectionError(f"could not open write pipe {self.wpipe}: {e}") from e
        try:
            self.fd_r = _open_nonblock(self.rpipe, os.O_RDONLY)
        except OSError as e:
            raise ConnectionError(f"could not open read pipe {self.rpipe}: {e}") from e
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.fd_r, selectors.EVENT_READ)
        self.closed = False

    def send_raw(self, frame_bytes) -> None:
        if not isinstance(frame_bytes, (bytes, bytearray)):
            frame_bytes = bytes(frame_bytes)
        L = len(frame_bytes) + 1
        if L > 255:
            raise ValueError("Frame too large for 1-byte length")
        with self._wlock:
            try:
                os.write(self.fd_w, bytes([L]) + frame_bytes)
            except BrokenPipeError as e:
                raise ConnectionError("writer pipe disconnected") from e 

    def inject_air_frame_with_meta(self, frame_bytes):
        self.send_raw(frame_bytes)

    def send_pkt(self, pkt):
        raw = bytes(pkt)
        self.send_raw(raw)

    def receive_raw(self, parse=True, timeout=0.8, debug=False):
        events = self.sel.select(timeout)
        for key, _ in events:
            if key.fileobj != self.fd_r:
                continue
            L = _read_exact(self.fd_r, 1)[0]
            if debug:
                print(f"[DBG] L={L}")
            if L <= 1:
                    return None
            payload = _read_exact(self.fd_r, L-1)
            if debug:
                print(f"[DBG] payload={payload.hex(' ')}")
            if not parse:
                return payload
            try:
                raw_bytes = bytes(payload)
                pkt = Dot15d4(raw_bytes)
                print(f"[RX] {pkt.summary()}")
                return pkt
            except Exception:
                return payload
        return None

    def receive_all(self, *, parse=False, drain_ms=50) -> List[Tuple[float, Union[bytes, Dot15d4]]]:
        out: List[Tuple[float, Union[bytes, Dot15d4]]] = []
        deadline = time.time() + drain_ms / 1000.0
        while time.time() < deadline:
            res = self.receive_raw(parse=parse, timeout=0.0)
            if res is None:
                break
            out.append(res)
        return out

    def close(self):
        try:
            if getattr(self, "sel", None):
                try:
                    self.sel.unregister(self.fd_r)
                except Exception:
                    pass
            try:
                self.sel.close()
            except Exception:
                pass
        except Exception:
            pass

        for attr in ("fd_r", "fd_w"):
            fd = getattr(self, attr, None)
            if isinstance(fd, int):
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, attr, None)

        self.sel = None
        self.closed = True


    


