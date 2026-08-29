#!/usr/bin/env bash
# Build both Helios/Selene C++ extensions in place, next to this script.
#
#   helioselene_ct        the default binding used in the project. It is 
#                         constant-time, uses Montgomery ladder, plus 
#                         Straus and a bucket MSM
#   helioselene_bindings  the stock OpenSSL bindings (variable-time wNAF).
#                         Benchmark only. No code calls it. 
#
# Requires: g++ (C++17), pybind11 (pip install pybind11) and OpenSSL dev headers.
#
set -euo pipefail
cd "$(dirname "$0")"

PY=${PYTHON:-python3}
SUF=$("$PY" -c "import sysconfig;print(sysconfig.get_config_var('EXT_SUFFIX'))")
PYINC=$("$PY" -c "import sysconfig;print(sysconfig.get_path('include'))")
PBINC=$("$PY" -c "import pybind11;print(pybind11.get_include())")

for mod in helioselene_ct helioselene_bindings; do
    g++ -O3 -shared -std=c++17 -fPIC -fvisibility=hidden \
        -I"$PYINC" -I"$PBINC" \
        "${mod}.cpp" -o "${mod}${SUF}" -lcrypto
    echo "built ${mod}${SUF}"
done
