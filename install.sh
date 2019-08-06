#!/bin/bash

mkdir -p ~/.portmon
cp portmon.service /lib/systemd/system/portmon.service
cp portmon.py /usr/bin/portmon.py
systemctl start portmon.service
systemctl enabled portmon.service
