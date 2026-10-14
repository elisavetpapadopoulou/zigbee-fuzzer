#!/usr/bin/env bash

# This script sets up the python environment if it doesn't exist yet.
# It should be sourced (i.e. called with "source scripts/setup_venv.sh")
# so that the python environment will be available in the calling shell.

if [ -d "venv" ]; then
    # shellcheck source=/dev/null
    source venv/bin/activate
else
    python3 -m venv venv
    # shellcheck source=/dev/null
    source venv/bin/activate
    pip3 install -r requirements.txt
fi

if ! command -v mvn >/dev/null 2>&1; then
    echo "Maven (mvn) is not on PATH. The Python venv does not provide it."
    echo "Install a Java 21 JDK and Maven, then run: mvn package"
elif ! command -v java >/dev/null 2>&1; then
    echo "java is not on PATH. Install a Java 21 JDK before: mvn package"
fi
