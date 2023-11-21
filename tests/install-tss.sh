#!/bin/bash

set -ex
git clone https://git.code.sf.net/p/ibmtpm20tss/tss
pushd tss 1>/dev/null || exit 1
autoreconf -i && ./configure --disable-tpm-1.2 --disable-hwtpm && make -j"$(nproc)" && sudo make install
popd 1>/dev/null
rm -rf tss
