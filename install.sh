#!/bin/bash

mkdir -p ~/.portmon
cp portmon.service /lib/systemd/system/portmon.service
cp portmon.py /usr/bin/portmon.py
cp -R bottle/ /usr/bin/
cp -n portmon.ini ~/.portmon/portmon.ini
systemctl enable --now portmon.service
