#!/usr/bin/env bash

# This script sets up the python environment if it doesn't exist yet.
# It should be sourced (i.e. called with "source scripts/setup_venv.sh")
# so that the python environment will be available in the calling shell.
#
# Jep is compiled against the JDK, so JAVA_HOME must point at a JDK
# (Java 21) before pip can install it.

_zigbee_setup_fail() {
    echo "$*" >&2
    return 1
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

if ! python -c "import jep" 2>/dev/null; then
    echo "jep did not import. pip often fails to build it without a JDK and Python headers."
    echo "  sudo apt install python3-dev g++ openjdk-21-jdk"
    echo "  export JAVA_HOME=\$(dirname \$(dirname \$(readlink -f \$(which java))))"
    echo "  python -m pip install --force-reinstall --no-cache-dir jep==4.3.2"
    echo "Then check with:  python -c \"import jep; print(jep.__file__)\""
    echo "(Use venv python, not a different python3.)"
    return 1
fi

echo "jep OK: $(python -c 'import jep, pathlib; print(pathlib.Path(jep.__file__).parent)')"

if ! command -v mvn >/dev/null 2>&1; then
    echo "Maven (mvn) is not on PATH. The Python venv does not provide it."
    echo "Install a Java 21 JDK and Maven, then run: mvn package"
elif ! command -v java >/dev/null 2>&1; then
    echo "java is not on PATH. Install a Java 21 JDK before: mvn package"
fi
