#!/bin/bash

mkdir ~/.portmon
cp portmon.service /lib/systemd/system/portmon.service
cp portmon.py /usr/bin/portmon.py
systemctl enabled portmon.service
