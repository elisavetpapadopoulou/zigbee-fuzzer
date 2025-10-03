#!/usr/bin/env python3

import threading
import socket, struct, time
from typing import Optional, Callable

from scapy.all import deque

HDLC_FLAG = 0x7E
HDLC_ESC = 0x7D
HDLC_XOR = 0x20

CMD_PROP_VALUE_GET = 0x02
CMD_PROP_VALUE_SET = 0x03
CMD_PROP_VALUE_IS = 0x06

PROP_PROTOCOL_VERSION = 0x0001
PROP_NCP_VERSION = 0x0002
PROP_INTERFACE_TYPE = 0x0003
PROP_CAPS = 0x0009
PROP_PHY_ENABLED = 0x0020
PROP_PHY_CHAN = 0x0021
PROP_MAC_RAW_STREAM_ENABLED = 0x0055
PROP_STREAM_RAW = 0x0071
PROP_LAST_STATUS = 0x0000
PROP_PHY_CCA_THRESHOLD = 0x0024
PROP_PHY_TX_POWER = 0x0025
PROP_PHY_RSSI = 0x0026
PROP_PHY_RX_SENSITIVITY = 0x0027

# SPINEL_STATUS_OK = 
SPINEL_STATUS_RESET_POWER_ON = 0x70
SPINEL_STATUS_RESET_EXTERNAL = 0x71
SPINEL_STATUS_RESET_SOFTWARE = 0x72

def hexdump(b: bytes) -> str:
    return ' '.join(f'{x:02x}' for x in b)

def crc16_ibm(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1)^0xA001 if (crc&1) else (crc>>1)
    return crc & 0xFFFF

def crc16_x25(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if (crc & 1) != 0:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    return (~crc) & 0xFFFF

def hdlc_frame(payload: bytes) -> bytes:
    f = payload + struct.pack("<H", crc16_x25(payload))
    out = bytearray()
    for b in f:
        if b in (HDLC_FLAG, HDLC_ESC):
            out += bytes([HDLC_ESC, b ^ HDLC_XOR])
        else:
            out.append(b)
    framed = bytes([HDLC_FLAG]) + bytes(out) + bytes([HDLC_FLAG])
    # #print("TX: Frame:", hexdump(framed))
    return framed

def hdlc_deframe(buf: bytearray):
    frames = []
    while True:
        try:
            start = buf.index(HDLC_FLAG)
        except ValueError:
            buf.clear()
            break
        if start > 0:
            del buf[:start]

        try:
            end = buf.index(HDLC_FLAG, 1)
        except ValueError:
            break

        raw = bytes(buf[1:end])

        if not raw:
            del buf[0:1]
            continue

        unesc = bytearray()
        k = 0
        while k < len(raw):
            v = raw[k]
            if v == HDLC_ESC:
                if k+1 >= len(raw):
                    return frames
                unesc.append(raw[k+1]^HDLC_XOR)
                k += 2
            else:
                unesc.append(v)
                k += 1
        if len(unesc) < 2:
            break

        payload = bytes(unesc[:-2])
        rxcrc = struct.unpack("<H", unesc[-2:])[0]
        calc = crc16_x25(payload)
        #print("RX Frame:", hexdump(bytes([HDLC_FLAG]) + unesc + bytes([HDLC_FLAG])))
        #print(f"RX Payload: {hexdump(payload)} CRC rx={rxcrc:04x} calc={calc:04x}")
        del buf[:end+1]
        if calc == rxcrc:
            frames.append(payload)
        else:
            #print("!! CRC mismatch, dropping")
            continue
    return frames


def make_header(tid:int, iid: int = 0)->int: 
    return 0x80 | ((iid & 0x3) << 4 ) | (tid & 0x0F)

def varint_decode(b: bytes, off: int = 0):
    val = 0
    shift = 0
    i = off
    while True:
        c = b[i]
        val |= (c & 0x7F) << shift
        i += 1
        if (c & 0x80) == 0:
            break
        shift += 7
    return val, i

def varint_encode(u: int)->bytes:
    out = bytearray()
    v = u & 0xFFFFFFFF
    while True:
        byte = v & 0x7F
        v >>= 7
        if v:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)

def send_reset_indication(send_fn, reason: int = 3, iid: int = 0):
    # header(TID=0) | CMD_RESET(1) | UINT8 reason
    payload = bytes([make_header(0, iid)]) + varint_encode(1) + bytes([reason])
    send_fn(payload)


def property_last_status_is(tid, status, iid=0):
    return bytes([make_header(tid, iid)]) + varint_encode(CMD_PROP_VALUE_IS) + varint_encode(status)


def enc_u16(x:int)->bytes: return struct.pack("<H", x)
def enc_u32(x:int)->bytes: return struct.pack("<I", x)
def enc_str(s:str)->bytes: return s.encode()+b'\x00'

def property_value_is(tid, pid, val, iid=0):
    return bytes([make_header(tid, iid)]) + varint_encode(CMD_PROP_VALUE_IS) + varint_encode(pid) + val

def property_value_set(tid, iid, prop, value):
    hdr = bytes([make_header(tid, iid)])
    body = varint_encode(CMD_PROP_VALUE_SET) + varint_encode(prop) + value
    return hdr + body

def _read_block(b: bytes, off: int):
    n, k = varint_decode(b, off)
    return b[k:k+n], k+n

class zigbeeOnHostDriver:
    def __init__(self, host="127.0.0.1", port=6000):
        self.host = host
        self.port = port
        self.sock:Optional[socket.socket]=None
        self.buf = bytearray()
        self._tx_queue = deque()
        self._rx_queue = deque()
        self._q_lock = threading.Lock()
        self.connected = threading.Event()

        def _on_host_tx(pdu: bytes):
            with self._q_lock:
                self._tx_queue.append(bytes(pdu))

        if not hasattr(self, "on_host_tx") or self.on_host_tx == (lambda f: None):
            self.on_host_tx = _on_host_tx

    def enable_raw(self):
        prop_id = 55
        value = b"\x01"
        frame = property_value_set(1, 0, prop_id, value)
        self._send(frame)

    def wait_connect(self, timeout_s = 15.0):
        return self.connected.wait(timeout_s)

    def pop_host_tx(self):
        with self._q_lock:
            return self._tx_queue.popleft() if self._tx_queue else None

    def peek_host_tx(self):
        with self._q_lock:
            return self._tx_queue[0] if self._tx_queue else None

    def _send(self, payload:bytes):
        if not self.sock:
            return
        framed = hdlc_frame(payload)
        print("_send():", ' '.join(f'{b:02x}' for b in payload))
        self.sock.sendall(framed)

    def receive_raw(self):
        with self._q_lock:
            raw_with_meta = self._rx_queue.popleft() if self._rx_queue else None
            if raw_with_meta is None:
                return None
            return raw_with_meta[:-4] if len(raw_with_meta) >= 4 else raw_with_meta

    def push_injected_raw(self, mac_pdu_with_meta:bytes):
        with self._q_lock:
            self._rx_queue.append(bytes(mac_pdu_with_meta))

    def send_last_status(self, tid, status, iid=0):
        payload = bytes([make_header(tid, iid)]) \
                + varint_encode(CMD_PROP_VALUE_IS) \
                + varint_encode(PROP_LAST_STATUS) \
                + varint_encode(status)
        self._send(payload)

    def inject_air_frame_with_meta(self, mac_pdu:bytes):
        # meta = struct.pack("<bBH", -40, 200, 0x0000)
        # payload = varint_encode(len(mac_pdu)) + mac_pdu 
        frame = property_value_is(0, PROP_STREAM_RAW, mac_pdu)
        self._send(frame)

    def _handle_get(self, tid:int, pid:int)->bytes:
        if pid ==  PROP_PROTOCOL_VERSION:
            return property_value_is(tid, pid, bytes([4, 3]))
        if pid == PROP_INTERFACE_TYPE:
            return property_value_is(tid, pid, enc_u32(0))
        if pid == PROP_CAPS:
            return property_value_is(tid, pid, b"")
        if pid ==  PROP_NCP_VERSION:
            return property_value_is(tid, pid, enc_str("zoh-min"))
        if pid == PROP_PHY_CCA_THRESHOLD:
            return property_value_is(tid, pid, struct.pack("b", -75))
        if pid == PROP_PHY_TX_POWER:
            return property_value_is(tid, pid, struct.pack("b", 0))
        if pid == PROP_PHY_RSSI:
            return property_value_is(tid, pid, struct.pack("b", -40))
        if pid == PROP_PHY_RX_SENSITIVITY:
            return property_value_is(tid, pid, struct.pack("b", -100))
        return property_value_is(tid, pid, b"")

    def _dispatch(self, payload:bytes):
        if len(payload) < 2:
            return
        hdr = payload[0]
        tid = hdr & 0x0F
        cmd, i = varint_decode(payload, 1)
        # print(f"DISPATCH: tid={tid} cmd={cmd}")
        if cmd == 1:
            send_reset_indication(self._send, reason=3)
            self.send_last_status(tid, SPINEL_STATUS_RESET_SOFTWARE)

            self._send(property_value_is(0, PROP_PROTOCOL_VERSION, bytes([4,3])))
            self._send(property_value_is(0, PROP_NCP_VERSION, enc_str("zoh-min")))
            self._send(property_value_is(0, PROP_INTERFACE_TYPE, enc_u32(0)))
            return
        if cmd == CMD_PROP_VALUE_GET:
            pid, _ = varint_decode(payload, i)
            # print(f"GET pid=0x{pid:04x}")
            self._send(self._handle_get(tid, pid))
            return
        elif cmd == CMD_PROP_VALUE_SET:
            pid, j = varint_decode(payload, i)
            # print(f"SET pid=0x{pid:04x}")
            if pid == PROP_STREAM_RAW:
                frame, _ = _read_block(payload, j)
                print(f"\n[COORDINATOR-TX]: Hex: {hexdump(frame)}")
                # self.on_host_tx(val)
                try:
                    from scapy.layers.dot15d4 import Dot15d4
                    pkt = Dot15d4(frame)
                    print(f"  Decoded: {pkt.summary()}")
                except:
                    pass
                # ACK the transmission
                self.send_last_status(tid, 0)
                meta = struct.pack("<bBH", -40, 200, 0x0000)
                with self._q_lock:
                    self._rx_queue.append(frame+meta)
                return

            val = payload[j:]

            # if pid in (PROP_PHY_ENABLED, PROP_PHY_CHAN):
            #     self._send(property_value_is(tid, pid, val))
            self._send(property_value_is(tid, pid, val))
            return

        elif cmd == CMD_PROP_VALUE_IS:
            pid, j = varint_decode(payload, i)
            # print(f"IS pid=0x{pid:04x}")
            if pid == PROP_STREAM_RAW:
                frame, _ = _read_block(payload, j)
                meta = struct.pack("<bBH", -40, 1, 0x0104)
                with self._q_lock:
                    self._rx_queue.append(frame + meta)
                val = payload[j:]
                self._send(property_value_is(tid, pid, val))
            return

    def serve_once(self, startup_delay = 5.0, accept_timeout = 0.5):
        #print("Starting minimal RCP server...", flush=True)
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(1)
        self.server = server
        #print(f"Listening on {self.host}:{self.port}", flush=True)
        conn, peer = server.accept()
        #print(f"Accepted from {peer}", flush=True)
        self.sock = conn
        self.sock.settimeout(0.1)
        self.connected.set()
        try:
            while True:
                if self.sock is None:
                    break
                try:
                    data = self.sock.recv(4096)
                except socket.timeout:
                    continue
                except OSError as e:
                    #print("recv OSError, exiting server loop:", e)
                    break
                if not data:
                    #print("Peer closed", flush=True)
                    break

                #print(f"RECV {len(data)} bytes: {hexdump(data)}", flush=True)
                self.buf.extend(data)
                deframed = hdlc_deframe(self.buf)
                #print(deframed)
                for pl in deframed:
                    self._dispatch(pl)
        finally:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

    def close(self):
        try:
            # close client connection
            if getattr(self, "sock", None):
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None
            # close server listener if present
            if getattr(self, "server", None):
                try:
                    self.server.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    self.server.close()
                except Exception:
                    pass
                self.server = None
        except Exception as e:
            # don't raise on close
            print("[driver.close] exception:", e)

        # clear queues
        with self._q_lock:
            self._tx_queue.clear()
            self._rx_queue.clear()


if __name__ == '__main__':
    driver = zigbeeOnHostDriver()

    def host_tx_handler(b):
        time.sleep(0.02)
        driver.inject_air_frame_with_meta(b)




