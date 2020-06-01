#!/bin/bash

systemctl stop portmon.service
systemctl disable portmon.service
rm /lib/systemd/system/portmon.service
rm /usr/bin/portmon.py
rm -r /usr/bin/bottle
systemctl daemon-reload
systemctl reset-failed
