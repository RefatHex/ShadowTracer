#!/bin/bash

[ "$(/var/ossec/bin/shadowtracer-control status | grep -E 'clusterd is running|apid is running' | wc -l)" == 2 ] || exit 1
exit 0
