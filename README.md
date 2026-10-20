# Zigbee-Fuzzer

This is a test setup to apply protocol state fuzzing to Zigbee coordinators and stacks. It is built upon the [ProtocolState-Fuzzer](https://github.com/protocol-fuzzing/protocol-state-fuzzer) framework and can be used to either test a hardware IEEE 802.15.4 adapter over-the-air or to test a Zigbee-on-Host (or ZBOSS) stack in a Linux process.

* **`src/`** contains code that configures ProtocolState-Fuzzer (PSF) and acts as a bridge between PSF and the mapper. This is done using [jep](https://github.com/ninia/jep), which allows embedding a CPython interpreter in a Java process.
* **`py/`** contains the mapper. `ZigbeeSUL` uses Scapy to construct and parse IEEE 802.15.4 / Zigbee packets. The radio or stack is selected in `py/config.yaml` (`driver_type`: `hardware`, `zoh`, or `zboss`).
* **`experiments/alphabets/`** contains different alphabets (subsets of Zigbee packet types) that can be used for testing. Use `association-nwkEntering.xml` for learning; it matches the symbols the mapper implements.
* **`experiments/args/`** contains test configurations (lists of PSF arguments) for setups that have already been used.
* **`experiments/results/`** contains results after tests have been run.
* **`experiments/tests/`** contains test sequences of interest (e.g., replaying specific sequences to reproduce bugs).
* **`scripts/`** contains miscellaneous scripts for resetting targets and setting up the Python environment.

---

## 1. Prerequisites

A Linux environment is required. The Python virtual environment does **not** install Maven or the JDK.

| Tool | Why |
| --- | --- |
| **Java 21 JDK** | Compile and run the shaded jar |
| **Maven** | Build the project (`mvn package`) |
| **Python 3** | Mapper runtime and Scapy packet parsing |
| **libffi & C++ compiler** | Compile `cffi` and `jep` native extensions |
| **graphviz (`dot`)** | Export learned Mealy machine models to PDF |

### Zigbee-Fuzzer clone repo

```sh
git clone https://github.com/elisavetpapadopoulou/zigbee-fuzzer.git
```

### Package Installation (Debian / Ubuntu)

```sh
sudo apt install -y openjdk-21-jdk maven graphviz python3 python3-venv python3-pip python3-dev libffi-dev g++
```

### Verification

Ensure toolchains are accessible and Maven points to Java 21:

```sh
java -version
mvn -version
python3 --version
dot -V
```

`mvn -version` must report runtime `Java version: 21`. 

---

## 2. Build the Fuzzer

### 2.1 Set `JAVA_HOME`

JEP compiles native C bindings during installation and requires `JAVA_HOME` pointing to a JDK:

```sh
export JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(which java)")")")"
```
```sh
echo "$JAVA_HOME"
# Expected output similar to: /usr/lib/jvm/java-21-openjdk-amd64
```

### 2.2 Initialize the Python Environment

Run the setup script from the repository root to create the local virtual environment (`venv/`) and build dependencies (including **jep 4.3.2** and **pycryptodomex**):

```sh
source scripts/setup_venv.sh
```

### 2.3 Compile the Java Jar

Build the shaded executable jar (the virtual environment can stay active; Maven does not interfere with it):

```sh
mvn package
```

The compiled artifact is generated at `target/zigbee-fuzzer-1.0-SNAPSHOT.jar`.

---

## 3. Configure the Mapper

Target selection is controlled through `py/config.yaml`. **`driver_type` is what selects the SUT**, not the Java flags.

| Field | Description |
| --- | --- |
| `driver_type` | `zoh` (default), `hardware`, or `zboss` |
| `zoh_host` / `zoh_port` | TCP server address bound by the fuzzer (default `127.0.0.1:6000`) |
| `zoh_mac` | Coordinator IEEE address expected by the mapper (`0x6c63696c63696c63`) |
| `zoh_timeout` | Seconds to wait for stack responses before timing out |
| `zoh_restart_cmd` | Command executed to reset/form ZOH between queries (`scripts/restartZOHStack.sh`) |
| `hardware_mac` | Coordinator IEEE for over-the-air hardware runs |
| `hardware_port` | Reference port; the **serial device actually opened** is passed via Java `-adapter` |
| `baud_rate` / `channel` | Adapter UART baud rate and 802.15.4 radio channel (default `115200`, channel `20`) |
| `hardware_restart_cmd` | Command executed to reset the hardware coordinator between queries |

* Always specify `-alphabet experiments/alphabets/association-nwkEntering.xml`. Do not omit it, as default fallback symbols are not implemented by the mapper.
* Java command-line flags require `-adapter` and `-connect`. When `driver_type` is `zoh`, pass dummy strings (e.g., `-adapter unused -connect unused`).

---

## 4. Run an Experiment (Zigbee-on-Host)

Zigbee-on-Host (ZOH) allows software testing without physical RF hardware by having the stack connect to the fuzzer over a local TCP socket (`127.0.0.1:6000`).

### 4.1 Install and Configure Zigbee-on-Host

1. **Clone ZOH and checkout the verified commit:**
   (See zigbee-on-host github for more information)
   ```sh
   git clone https://github.com/Nerivec/zigbee-on-host.git
   ```
   ```sh
   cd zigbee-on-host
   ```
   ```sh
   git checkout fab65af
   ```
   ```sh
   npm install
   ```
   ```sh
   npm run build
   ```

2. **Configure the virtual socket adapter:**
   Edit `dist/dev/conf.json`'s adapter path field so ZOH connects to the fuzzer's TCP bridge:
   ```sh
   vi dist/dev/conf.json
   ```
   ```sh
   ...
       "adapter": {
           "path": "tcp://127.0.0.1:6000"
      }
   ...
   ```

3. **Export the path in your shell:**
   Return to `zigbee-fuzzer` and point `ZOH_ROOT` to your cloned tree:
   ```sh
   export ZOH_ROOT=/path/to/zigbee-on-host
   ```

### 4.2 Smoke-Test the Mapper

Replay a short association test sequence from the fuzzer repository root. This checks JEP, Python imports, and that ZOH joins and exchanges frames with the fuzzer:

```sh
source scripts/setup_venv.sh
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/zoh_args \
  -test experiments/tests/simple_hw_test.txt \
  -times 1
```


### 4.3 Learning Runs

* **Short learning trial (capped rounds):**
  ```sh
  mkdir -p experiments/results/zoh-smoke
  java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/zoh_args \
    -output experiments/results/zoh-smoke \
    -roundLimit 4
  ```

* **Full learning run:**
  ```sh
  mkdir -p experiments/results/zoh
  java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/zoh_args \
    -output experiments/results/zoh
  ```

---

## 5. Run an Experiment (Hardware)

Hardware testing requires:
* An IEEE 802.15.4 USB adapter for packet injection (default baud 115200).
* A physical coordinator on **channel 20** (matching `py/config.yaml`) with its IEEE configured in `hardware_mac`.

### 5.1 Configuration

Edit `py/config.yaml`:

```yaml
driver_type: "hardware"
hardware_mac: 0x00124b003a053efe   # Set to coordinator IEEE
channel: 20
```

If using `scripts/restartSonoffCoord.sh` for coordinator resets:

```sh
export HARDWARE_SETUP=/absolute/path/to/hardware_setup
export SONOFF_PORT=/dev/ttyUSB0
```

Locate the injection adapter device:

```sh
ls /dev/ttyACM* /dev/serial/by-id/*
```

### 5.2 Execute Hardware Run

From the repository root:

```sh
source scripts/setup_venv.sh
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/hw_args \
  -adapter /dev/ttyACM0 \
  -output experiments/results/hardware_trial \
  -roundLimit 4
```

---

## 6. Output Artifacts

In the `-output` directory, ProtocolState-Fuzzer writes:

| File | Description |
| --- | --- |
| `learnedModel.dot` | Final learned state machine hypothesis |
| `hyp1.dot`, `hyp2.dot`, … | Intermediate hypotheses generated per learning round |
| `statistics.txt` | Query counts, cache performance, and runtime timing |
| `alphabet.xml` | Snapshot of the alphabet configuration used |
| `command.args` | Copy of the command-line flags for reproducibility |
| `error.msg` | Error details if a test run terminates unexpectedly |

Render learned models to PDF using Graphviz:

```sh
dot -Tpdf experiments/results/zoh/learnedModel.dot -o learnedModel.pdf
```

---

## 7. Troubleshooting

| Symptom | Likely Cause | Solution |
| --- | --- | --- |
| `fatal error: ffi.h: No such file or directory` | Missing CFFI build header | Run `sudo apt install libffi-dev` and re-run `source scripts/setup_venv.sh`. |
| `Failed to import encodings module` | `PYTHONHOME` set to venv prefix | Run `unset PYTHONHOME`. Ensure `setup_venv.sh` does not export `PYTHONHOME`. |
| `No module named 'Cryptodome'` | Wrong package variant installed | Ensure `pycryptodomex` is listed in `requirements.txt` instead of `pycryptodome`. |
| `jep package not found` / missing `libjep.so` | JEP failed compilation during pip install | Ensure `JAVA_HOME` points to JDK 21, install `python3-dev g++`, and run: `python -m pip install --force-reinstall --no-cache-dir jep==4.3.2`. |
| `Jep is not supported in standalone Python` | Expected behavior | Do not run `import jep` directly in Python; JEP must be initialized through the JVM. |
| `TimeoutError: Zigbee stack did not connect in time` | ZOH not connecting on TCP 6000 | Verify `ZOH_ROOT`, ensure `dist/dev/conf.json` specifies `"path": "tcp://127.0.0.1:6000"`, and check `.logs/dev-cli.log`. |
| `npm ERR! Missing script: "dev:cli"` | Untracked upstream commit in ZOH | In the ZOH tree, run `git checkout fab65af` and rebuild with `npm run build`. |
| `mvn: command not found` | Maven not installed or missing from `PATH` | Run `sudo apt install maven` or load the environment module. |

---

## Credits

* State fuzzer integration follows [protocol-fuzzing/ble-fuzzer](https://github.com/protocol-fuzzing/ble-fuzzer).
* Hypothesis comparison utilities adapted from [protocol-fuzzing/edhoc-fuzzer](https://github.com/protocol-fuzzing/edhoc-fuzzer).
