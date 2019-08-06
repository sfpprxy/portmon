#!/bin/bash

systemctl stop portmon.service
systemctl disable portmon.service
rm /lib/systemd/system/portmon.service
rm /usr/bin/portmon.py
systemctl daemon-reload
systemctl reset-failed
