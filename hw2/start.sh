#!/bin/sh

# disable ASLR
sudo sysctl -w kernel.randomize_va_space=0
