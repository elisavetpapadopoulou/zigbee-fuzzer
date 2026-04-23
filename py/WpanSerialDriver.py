import serial
import time
import subprocess
from typing import Optional, List


SLIP_END = 0xC0
SLIP_ESC = 0xDB
SLIP_ESC_END = 0xDC
SLIP_ESC_ESC = 0xDD


class WpanSerialDriver:
    def __init__(
            self,
            port="/dev/ttyACM1",
            baudrate=115200,
            timeout=0.2,
            restart_cmd=None,
            restart_wait_s=5.0,
            stop_cmd=["pkill", "-f", "sonoff_coord_app.py"]
        ):

        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.restart_cmd = restart_cmd
        self.restart_wait_s = restart_wait_s
        self.stop_cmd = stop_cmd
        self.ser: Optional[serial.Serial] = None
        self.seq = 0

    def open(self, timeout_s=20.0):
        deadline = time.time() + timeout_s
        last_err = None

        while time.time() < deadline:
            try:
                self.ser = serial.Serial(self.port, self.baudrate, timeout=self.timeout)
                time.sleep(1.5)

                self.ser.reset_input_buffer()
                self.ser.reset_output_buffer()
                time.sleep(0.3)
                self.ser.reset_input_buffer()
                self._slip_resync(1.0)
                return
            except Exception as e:
                last_err = e
                self.ser = None
                time.sleep(0.5)

        raise last_err

    def close(self):
        if self.ser is not None:
            try:
                if self.ser.is_open:
                    self.ser.close()
            finally:
                self.ser = None

    def _stop_stack(self):
        """
        Compatibility no-op so ZigbeeSUL.close() does not fail when using the
        serial injector instead of zigbeeOnHostDriver.
        """
        if self.stop_cmd:
            subprocess.run(self.stop_cmd, check=False)

    def restart(self):
        self.close()
        if not self.restart_cmd:
            raise RuntimeError("No restart command configured for this driver")

        subprocess.run(self.restart_cmd, check=True)
        time.sleep(self.restart_wait_s)
        self.open()

    def reboot_firmware(self):
        """
        Send:
            !X
        Reboots the nRF firmware.
        """
        payload = bytes([ord("!"), ord("X")])
        self._send_raw_packet(payload)

    def enter_promiscuous_mode(self):
        payload = bytes([ord("!"), ord("P")])
        self._send_raw_packet(payload)

    # -------------------------
    # SLIP helpers
    # -------------------------

    @staticmethod
    def slip_encode(data: bytes) -> bytes:
        out = bytearray()
        for b in data:
            if b == SLIP_END:
                out.extend([SLIP_ESC, SLIP_ESC_END])
            elif b == SLIP_ESC:
                out.extend([SLIP_ESC, SLIP_ESC_ESC])
            else:
                out.append(b)
        out.append(SLIP_END)
        return bytes(out)

    def slip_read_packet(self, timeout: float = 1.0) -> Optional[bytes]:
        if self.ser is None:
            raise RuntimeError("Serial port is not open")

        end_time = time.time() + timeout
        buf = bytearray()
        esc = False

        while time.time() < end_time:
            b = self.ser.read(1)
            if not b:
                continue
            b = b[0]

            if esc:
                if b == SLIP_ESC_END:
                    buf.append(SLIP_END)
                elif b == SLIP_ESC_ESC:
                    buf.append(SLIP_ESC)
                else:
                    # malformed escape sequence -> drop current frame
                    buf.clear()
                esc = False
                continue

            if b == SLIP_ESC:
                esc = True
                continue

            if b == SLIP_END:
                if buf:
                    return bytes(buf)
                continue

            buf.append(b)

        return None

    def _slip_resync(self, timeout: float = 1.0):
        """
        Discard bytes until the next SLIP_END so that the next read starts on a
        clean packet boundary.
        """
        if self.ser is None:
            raise RuntimeError("Serial port is not open")

        end_time = time.time() + timeout
        while time.time() < end_time:
            b = self.ser.read(1)
            if not b:
                continue
            if b[0] == SLIP_END:
                return

    # -------------------------
    # Raw send helper
    # -------------------------

    def _send_raw_packet(self, payload: bytes):
        if self.ser is None:
            raise RuntimeError("Serial port is not open")
        self.ser.write(self.slip_encode(payload))
        self.ser.flush()

    # -------------------------
    # Commands
    # -------------------------

    def set_channel(self, channel: int):
        """
        Send:
            !C <channel>
        """
        if not (11 <= channel <= 26):
            raise ValueError(f"Invalid 802.15.4 channel: {channel}")

        payload = bytes([ord("!"), ord("C"), channel])
        self._send_raw_packet(payload)

    def set_addresses(self, pan_id: int, short_addr: int):
        """
        Send:
            !A <pan_id_le16> <short_addr_le16>

        Used after association succeeds so the firmware can install
        PAN ID / short address filters and auto-ACK coordinator unicasts.
        """
        if not (0 <= pan_id <= 0xFFFF):
            raise ValueError(f"Invalid PAN ID: 0x{pan_id:04x}")
        if not (0 <= short_addr <= 0xFFFF):
            raise ValueError(f"Invalid short address: 0x{short_addr:04x}")

        payload = (
            bytes([ord("!"), ord("A")]) +
            pan_id.to_bytes(2, "little") +
            short_addr.to_bytes(2, "little")
        )
        self._send_raw_packet(payload)

    def request_ieee(self):
        """
        Send:
            ?M
        """
        payload = bytes([ord("?"), ord("M")])
        self._send_raw_packet(payload)

    def inject_air_frame_with_meta(self, psdu: bytes) -> int:
        """
        Send one raw IEEE 802.15.4 PSDU using:
            !S <seq> <num_attr=0> <psdu>

        Returns the sequence number used by the injector protocol.
        """
        if len(psdu) == 0 or len(psdu) > 127:
            raise ValueError(f"Invalid PSDU length: {len(psdu)}")

        seq = self.seq & 0xFF
        self.seq = (self.seq + 1) & 0xFF

        payload = bytes([ord("!"), ord("S"), seq, 0]) + psdu
        self._send_raw_packet(payload)
        return seq

    # -------------------------
    # Parsing / receive helpers
    # -------------------------

    @staticmethod
    def _looks_like_debug_blob(pkt: bytes) -> bool:
        return (
            b"<dbg>" in pkt
            or b"<inf>" in pkt
            or b"wpan_serial:" in pkt
            or pkt.startswith(b"[00:")
        )

    @staticmethod
    def parse_packet(pkt: bytes) -> dict:
        """
        Known cases:
          !R seq status num_tx   -> tx report
          !M <8 bytes>           -> ieee address
          otherwise              -> rx frame / unknown
        """
        if len(pkt) >= 2 and pkt[0] == ord("!") and pkt[1] == ord("R"):
            if len(pkt) >= 5:
                return {
                    "type": "tx_report",
                    "seq": pkt[2],
                    "status": pkt[3],
                    "num_tx": pkt[4],
                    "raw": pkt,
                }

        if len(pkt) >= 2 and pkt[0] == ord("!") and pkt[1] == ord("M"):
            return {
                "type": "ieee_addr",
                "ieee_le": pkt[2:10],
                "raw": pkt,
            }

        return {
            "type": "rx_frame",
            "frame": pkt,
            "raw": pkt,
        }

    def recv_one(self, timeout: float = 1.0) -> Optional[dict]:
        pkt = self.slip_read_packet(timeout=timeout)
        if pkt is None:
            return None
        return self.parse_packet(pkt)

    def recv_many(self, timeout: float = 1.0, max_packets: int = 10) -> List[dict]:
        out = []
        deadline = time.time() + timeout
        while len(out) < max_packets and time.time() < deadline:
            rem = max(0.0, deadline - time.time())
            pkt = self.recv_one(timeout=rem)
            if pkt is None:
                break
            out.append(pkt)
        return out

    def receive_raw(self, timeout: Optional[float] = None) -> Optional[bytes]:
        end_time = time.time() + (self.timeout if timeout is None else timeout)

        while time.time() < end_time:
            pkt = self.slip_read_packet(timeout=max(0.0, end_time - time.time()))
            if pkt is None:
                return None

            print(f"[RAW SLIP] {time.time():.6f} {pkt.hex()} {pkt[:8]!r}")

            if self._looks_like_debug_blob(pkt):
                continue

            parsed = self.parse_packet(pkt)
            print(f"[PARSED TYPE] {parsed['type']}")

            if parsed["type"] == "rx_frame":
                return parsed["frame"]

        return None
