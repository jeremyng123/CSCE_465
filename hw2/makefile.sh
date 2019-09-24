#!/bin/bash

gcc -z execstack -z norelro -fno-stack-protector -o stack -O0 -m32 -no-pie stack.c
echo "gcc -z execstack -z norelro -fno-stack-protector -o stack -O0 -m32 -no-pie stack.c"
gcc exploit.c -o exploit
echo "gcc exploit.c -o exploit"

sudo chown root stack
echo "sudo chown root stack"
sudo chmod 4755 stack
echo "sudo chmod 4755 stack"
./exploit
