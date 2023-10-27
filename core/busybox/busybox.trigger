#!/bin/sh

[ -e /bin/bbsuid ] && /bin/bbsuid --install
[ -e /bin/busybox-extras ] && /bin/busybox-extras --install -s
/bin/busybox --install -s
