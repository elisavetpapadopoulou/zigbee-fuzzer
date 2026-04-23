import time, threading
from py.WpanSerialDriver import WpanSerialDriver
from py.zigbeeOnHostDriver import zigbeeOnHostDriver


def driver_factory(config, serial_port):
    driver_type = config.get("driver_type", "default")

    if driver_type in ["zoh", "default"]:
        return zigbeeOnHostDriver(
                host=config.zoh_host,
                port=config.zoh_port,
                restart_cmd=config.restart_cmd,
                restart_on_reset=True,
                restart_on_disconnect=True,
                restart_cooldown_s=2.0,
                )
    elif driver_type == "hardware":
        return WpanSerialDriver(serial_port, config.baud_rate)
    else:
        raise ValueError(f"Unknown driver type: {driver_type}")

def driver_pre(self, config, driver, timeout_s=30):
    if isinstance(driver, zigbeeOnHostDriver):
        print("First connection attempt...")
        if not getattr(self, "_srv_th", None):
            self._srv_th = threading.Thread(target=self.driver.serve_once, daemon=True)
            self._srv_th.start()
            time.sleep(7)
        else:
            self.driver._run_restart_cmd("manual-start")
        if not self.driver.wait_connect(timeout_s):
            raise TimeoutError("Zigbee stack did not connect in time")
        v = config["zoh_mac"]
        self.config["coord_ieee"] = int(v, 0) if isinstance(v, str) else int(v)

        print(f"driver_pre: coord_ieee set to {self.config['coord_ieee']:016x}")

        self.driver.wait_ready(7)

    elif isinstance(driver, WpanSerialDriver):
        driver.open()
        driver.set_channel(config.channel)
        time.sleep(5)
    else:
        raise ValueError(f"Unknown driver type: {type(driver)}")
