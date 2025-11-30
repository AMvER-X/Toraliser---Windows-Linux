#!/bin/bash

# Replace file path with file path on host machine.
export LD_PRELOAD = /home/jobj/code/toralize/toralize.so

#runs all args to the script
"${@}"

unset LD_PRELOAD