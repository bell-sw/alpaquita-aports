#!/bin/sh

export LD_PRELOAD=$(echo $LD_PRELOAD | sed -E 's,:*/lib/lib[a-z]+malloc[a-z-]*.so[0-9.]*,,g'):/lib/@LIB_NAME@
