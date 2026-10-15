#!/usr/bin/env bash

# This script sets up the python environment if it doesn't exist yet.
# It should be sourced (i.e. called with "source scripts/setup_venv.sh")
# so that the python environment will be available in the calling shell.
#
# Jep is compiled against the JDK, so JAVA_HOME must point at a JDK
# (Java 21) before pip can install it.
#
# Jep cannot be imported from standalone Python. A successful install
# is a jep package plus a native lib (libjep.so) that Java loads.

_zigbee_setup_fail() {
    echo "$*" >&2
    return 1
}

_zigbee_jep_dir() {
    python -c "
import importlib.util
import pathlib
import sys

spec = importlib.util.find_spec('jep')
if spec is None or not spec.origin:
    sys.exit('jep package not found')
print(pathlib.Path(spec.origin).parent)
"
}

_zigbee_jep_native() {
    python -c "
import pathlib
import sys

d = pathlib.Path(sys.argv[1])
if not (any(d.glob('libjep*')) or (d / 'jep.dll').exists()):
    sys.exit('jep package has no native library (libjep.so)')
" "$1"
}

if [ ! -d "venv" ]; then
    python3 -m venv venv || _zigbee_setup_fail "python3 -m venv venv failed"
fi

# shellcheck source=/dev/null
source venv/bin/activate

if [ -z "${JAVA_HOME:-}" ] && command -v java >/dev/null 2>&1; then
    _java_bin="$(command -v java)"
    if command -v readlink >/dev/null 2>&1; then
        _java_bin="$(readlink -f "$_java_bin" 2>/dev/null || echo "$_java_bin")"
    fi
    export JAVA_HOME="$(dirname "$(dirname "$_java_bin")")"
fi

echo "python:    $(command -v python)"
echo "JAVA_HOME: ${JAVA_HOME:-unset (jep install will likely fail)}"

python -m pip install --upgrade pip
python -m pip install -r requirements.txt || _zigbee_setup_fail "pip install -r requirements.txt failed"

# Do not use: python -c "import jep"
# jep 4.x raises ImportError on purpose unless it is running inside a JVM.
_jep_dir="$(_zigbee_jep_dir)" || _zigbee_setup_fail "jep Python package not found in this venv"
_zigbee_jep_native "$_jep_dir" || {
    echo "jep did not finish building. pip often fails without a JDK and Python headers."
    echo "  sudo apt install python3-dev g++ openjdk-21-jdk"
    echo "  export JAVA_HOME=\$(dirname \$(dirname \$(readlink -f \$(which java))))"
    echo "  python -m pip install --force-reinstall --no-cache-dir jep==4.3.2"
    echo "Then check with:  ls \"\$(python -c \"import importlib.util, pathlib; print(pathlib.Path(importlib.util.find_spec('jep').origin).parent)\")\"/libjep*"
    echo "(Use venv python, not a different python3.)"
    echo "python -c \"import jep\" is supposed to fail: jep only loads from Java."
    return 1
}

echo "jep OK: $_jep_dir"

export PYTHONHOME="${VIRTUAL_ENV}"
export LD_LIBRARY_PATH="${_jep_dir}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
echo "PYTHONHOME=$PYTHONHOME"
echo "LD_LIBRARY_PATH includes $_jep_dir"

if ! command -v mvn >/dev/null 2>&1; then
    echo "Maven (mvn) is not on PATH. The Python venv does not provide it."
    echo "Install a Java 21 JDK and Maven, then run: mvn package"
elif ! command -v java >/dev/null 2>&1; then
    echo "java is not on PATH. Install a Java 21 JDK before: mvn package"
fi
