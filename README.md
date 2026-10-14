# Zigbee-Fuzzer

This is a test setup to apply protocol state fuzzing to Zigbee coordinators and stacks. It is built upon the [ProtocolState-Fuzzer](https://github.com/protocol-fuzzing/protocol-state-fuzzer) framework and can be used to either test a hardware IEEE 802.15.4 adapter over-the-air or to test a Zigbee-on-Host (or ZBOSS) stack in a Linux process.

**src/** contains code that configures ProtocolState-Fuzzer (PSF) and acts as a bridge between PSF and the mapper. This is done using [jep](https://github.com/ninia/jep), which allows embedding a CPython interpreter in a Java process.

**py/** contains the mapper. `ZigbeeSUL` uses Scapy to construct and parse IEEE 802.15.4 / Zigbee packets. The radio or stack is selected in `py/config.yaml` (`driver_type`: `hardware`, `zoh`, or `zboss`).

**experiments/alphabets/** contains different alphabets (subsets of Zigbee packet types) that can be used for testing. Use `association-nwkEntering.xml` for learning; it matches the symbols the mapper implements.

**experiments/args/** contains test configurations (lists of PSF arguments) for setups that have already been used.

**experiments/results/** contains results after tests have been run.

**experiments/tests/** contains test sequences of interest. For example, specific test sequences can be run to reproduce bugs.

**scripts/** contains miscellaneous scripts for resetting targets and setting up the Python environment.

All commands below assume you are in the **repository root** with the Python venv **activated**. Java loads `py/` as a relative path (`sys.path.insert(0, 'py')`).

---

## 1. Prerequisites

Linux. The Python venv does **not** install Maven or the JDK.

| Tool | Why |
| --- | --- |
| Java **21** JDK | Compile and run the shaded jar |
| Maven | `mvn package` |
| Python 3 | Mapper + jep |
| graphviz (`dot`) | PSF exports learned models to PDF |

```sh
java -version
mvn -version
python3 --version
dot -V
```

`mvn -version` must report Java 21. On Debian/Ubuntu:

```sh
sudo apt install openjdk-21-jdk maven graphviz python3 python3-venv python3-pip
```

On a cluster, load the matching modules instead (`module load` Java 21 and Maven) so `java` and `mvn` are on `PATH`.

---

## 2. Build the fuzzer

```sh
source scripts/setup_venv.sh
mvn package
```

`setup_venv.sh` creates `venv/` if needed and installs `requirements.txt` (including **jep 4.3.2**, which must match the Java jep dependency in `pom.xml`). Leave the venv activated for every `java -jar` command.

You should get `target/zigbee-fuzzer-1.0-SNAPSHOT.jar`.

If Java cannot load jep after `mvn package`:

```sh
python3 -c "import jep, pathlib; print(pathlib.Path(jep.__file__).parent)"
export LD_LIBRARY_PATH="$(python3 -c "import jep, pathlib; print(pathlib.Path(jep.__file__).parent)"):$LD_LIBRARY_PATH"
```

---

## 3. Configure the mapper

Edit `py/config.yaml`. **`driver_type` is what selects the SUT**, not the Java flags.

| Field | Meaning |
| --- | --- |
| `driver_type` | `zoh` (default), `hardware`, or `zboss` |
| `zoh_host` / `zoh_port` | TCP address of Zigbee-on-Host (default `127.0.0.1:6000`) |
| `zoh_mac` | Coordinator IEEE used by the mapper (hex int, e.g. `0x6c63696c63696c63`) |
| `zoh_timeout` | Seconds to wait for a response |
| `zoh_restart_cmd` | Command run to reset ZOH between queries (default `scripts/restartZOHStack.sh`) |
| `hardware_mac` | Coordinator IEEE for over-the-air runs |
| `hardware_port` | Noted in yaml; the **serial device actually opened** is Java `-adapter` |
| `baud_rate` / `channel` | Adapter UART and 802.15.4 channel (default 115200, channel 20) |
| `hardware_timeout` | Seconds to wait for a response |
| `hardware_restart_cmd` | Reset the coordinator between queries |

Java still **requires** `-adapter` and `-connect`. `-connect` is currently **ignored** by Python (IEEE comes from this yaml). `-adapter` is used only when `driver_type` is `hardware`.

Use `experiments/alphabets/association-nwkEntering.xml`. Do **not** omit `-alphabet`: the packaged default still uses `APS_REQUEST_KEY` / `APS_VERIFY_KEY`, which the mapper does not implement.

---

## 4. Run an experiment (Zigbee-on-Host)

This is the path you can follow without an RF dongle, if you have a Zigbee-on-Host tree that exposes Spinel/raw frames on TCP port 6000.

### 4.1 Point the restart script at your ZOH tree

`scripts/restartZOHStack.sh` runs `npm run dev:cli form yes` in the ZOH directory (forms a coordinator, then the fuzzer joins). Override the default lab path:

```sh
export ZOH_ROOT=/absolute/path/to/zigbee-on-host
```

That tree must already build (`npm` / Node). First time, form a network once by hand if needed, and copy the coordinator IEEE into `py/config.yaml` as `zoh_mac`.

Leave `driver_type : "zoh"` in `py/config.yaml`.

### 4.2 Smoke-test the mapper (seconds)

Replay a short association-like sequence. This checks jep, Python imports, and that ZOH accepts frames, without running a full learner.

```sh
source scripts/setup_venv.sh
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/zoh_args \
  -test experiments/tests/simple_hw_test.txt \
  -times 1
```

If this hangs or times out, ZOH is not listening on `127.0.0.1:6000`, `ZOH_ROOT` is wrong, or `zoh_mac` does not match the coordinator. Watch `.logs/dev-cli.log` (created by the restart script).

### 4.3 Short learning run (minutes)

A bound of 5000 equivalence queries is a long thesis run. For a first experiment, cap the number of learning rounds:

```sh
mkdir -p experiments/results/zoh-smoke
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/zoh_args \
  -output experiments/results/zoh-smoke \
  -roundLimit 4
```

### 4.4 Full learning run (hours)

```sh
mkdir -p experiments/results/zoh
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/zoh_args
```

That uses `-equivalenceQueryBound 5000` and writes under `experiments/results/zoh`.

### 4.5 What to look at

In the `-output` directory PSF writes at least:

| File | Meaning |
| --- | --- |
| `learnedModel.dot` | Last hypothesis (open with xdot, or `dot -Tpdf`) |
| `hyp1.dot`, `hyp2.dot`, … | Intermediate hypotheses |
| `statistics.txt` | Query counts and timing |
| `alphabet.xml` | Copy of the alphabet used |
| `command.args` | Flags for that run |
| `error.msg` | Present if the run died |

```sh
dot -Tpdf experiments/results/zoh-smoke/learnedModel.dot -o learnedModel.pdf
```

---

## 5. Run an experiment (hardware)

You need:

- An IEEE 802.15.4 USB adapter the mapper can inject on (WPAN serial; default baud 115200).
- A coordinator on **channel 20** (or change `channel` in yaml) whose IEEE you put in `hardware_mac`.

### 5.1 Configure

In `py/config.yaml`:

```yaml
driver_type : "hardware"
hardware_mac : 0x00124b003a053efe   # your coordinator IEEE
channel : 20
```

If the coordinator is reset between queries via `scripts/restartSonoffCoord.sh`, point it at your helper tree and dongle:

```sh
export HARDWARE_SETUP=/absolute/path/to/hardware_setup
export SONOFF_PORT=/dev/ttyUSB0
```

That script restores a `baseline_backup.json` with `zigpy_znp` and starts `sonoff_coord_app.py`. Skip or edit it if you reset the coordinator some other way; then change `hardware_restart_cmd` in yaml accordingly.

Find the **mapper** adapter (not the coordinator UART):

```sh
ls /dev/serial/by-id/
ls /dev/ttyACM*
```

### 5.2 Smoke-test, then learn

```sh
source scripts/setup_venv.sh
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/hw_args \
  -adapter /dev/ttyACM0 \
  -test experiments/tests/simple_hw_test.txt \
  -times 1
```

Replace `/dev/ttyACM0` with your adapter. Then a short or full run:

```sh
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/hw_args \
  -adapter /dev/ttyACM0 \
  -output experiments/results/hardware_trial \
  -roundLimit 4
```

---

## 6. Arguments

Most required arguments are in `experiments/args` and can be passed by prefixing the file with `@`. Later flags override the file. A full learning command looks like this:

```sh
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar state-fuzzer-server \
  -output experiments/results/zoh \
  -alphabet experiments/alphabets/association-nwkEntering.xml \
  -equivalenceQueryBound 5000 \
  -logQueries \
  -adapter unused \
  -connect unused
```

**state-fuzzer-server** means that a server implementation (a coordinator / stack) is being fuzzed. This is the only supported mode.

**-output** directory for learned models and statistics.

**-alphabet** input symbols. Always pass `experiments/alphabets/association-nwkEntering.xml` for this mapper.

**-equivalenceQueryBound** how many tests to use when checking a hypothesis. `5000` is the value used in the arg files.

**-roundLimit** stop after this many learning rounds. Use this for a first experiment.

**-logQueries** log membership / equivalence queries.

**-adapter** required. Serial device for hardware; dummy string for `zoh` / `zboss`.

**-connect** required. Currently unused by the mapper; IEEE comes from `py/config.yaml`.

**-ceReruns** re-run a counterexample several times (helps with wireless non-determinism).

### Testing specific input sequences

```sh
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/zoh_args \
  -test experiments/tests/simple_hw_test.txt \
  -times 5
```

Symbols in the file must appear in the alphabet. `simple_hw_test.txt` matches `association-nwkEntering.xml`.

### Timing probe

To search wait values that reduce time-related non-determinism (`-test` plus `-probeCmd`):

```sh
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/zoh_args \
  -test experiments/tests/simple_hw_test.txt \
  -probeCmd responseWait,MAC_BEACON_REQUEST,MAC_ASSOCIATION_REQUEST,ZDO_NODE_DESCRIPTOR_REQUEST \
  -times 7 \
  -probeLow 0 \
  -probeHigh 20000 \
  -probeTol 25 \
  -probeExport timing_alphabet.txt
```

---

## 7. If something fails

| Symptom | Likely cause |
| --- | --- |
| `mvn: command not found` | JDK/Maven not installed; venv does not provide `mvn` |
| `mvn` uses Java 11/17 | Point `JAVA_HOME` at JDK 21 |
| `No module named 'yaml'` | Recreate venv or `pip install -r requirements.txt` |
| `from ZigbeeSUL import ZigbeeSUL` fails | Not running from the repo root, or venv not active |
| UnsatisfiedLinkError / jep | jep 4.3.2 missing in venv, or `LD_LIBRARY_PATH` (see §2) |
| Hang on ZOH connect | Nothing on port 6000, or `ZOH_ROOT` wrong |
| `KeyError` / unimplemented symbol | Alphabet is not `association-nwkEntering.xml` |
| Hardware opens the wrong tty | Pass `-adapter` (yaml `hardware_port` is not what Java opens) |

---

## Credits

* `src/**` PSF wiring follows [protocol-fuzzing/ble-fuzzer](https://github.com/protocol-fuzzing/ble-fuzzer)
* `scripts/diff_hyps.sh` is copied from [protocol-fuzzing/edhoc-fuzzer](https://github.com/protocol-fuzzing/edhoc-fuzzer)
