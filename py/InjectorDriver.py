import serial
import time

class InjectorDriver:
    def __init__(self, port="/dev/ttyACM0", baudrate=115200, timeout=1.0):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.ser = None

    def open(self):
        self.ser = serial.Serial(self.port, self.baudrate, timeout=self.timeout)
        time.sleep(0.5)

        # Drop boot/log noise
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()

    def close(self):
        if self.ser is not None:
            self.ser.close()
            self.ser = None

    def inject_air_frame_with_meta(self, mac_pdu: bytes):
        if self.ser is None:
            raise RuntimeError("Injector serial port is not open")

        if len(mac_pdu) == 0 or len(mac_pdu) > 127:
            raise ValueError(f"Invalid PSDU length: {len(mac_pdu)}")

        frame = bytes([len(mac_pdu)]) + mac_pdu
        self.ser.write(frame)
        self.ser.flush()

        # Read one line of status back
        line = self.ser.read_until(b"\n")
        return line

    def receive_raw(self):
        # TX-only injector for now
        return None
