#!/bin/bash
#
# Basic wrapper around python script.
#
# Assumptions:
# - config file is in same directory as script and called 'config.ini'
#


set -e
set -u


readonly script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"


cd "${script_dir}"
python ./auth_yubico.py --config=config.ini &>/dev/null &
echo $! >auth_yubico.pid


exit 0
