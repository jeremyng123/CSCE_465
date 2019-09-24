#!/bin/bash

# --== with stack guard and execstack ==--
gcc -z execstack -fno-stack-protector -o stack stack.c
echo "gcc -z execstack -fno-stack-protector -o stack stack.c"

gcc -z execstack -fno-stack-protector -o stack_dash stack_dash.c
echo "gcc -z execstack -fno-stack-protector -o stack_dash stack_dash.c"



# --== no stack guard ==--
gcc -z execstack -o stack_no_stack_prot stack.c
echo "gcc -z execstack -z -o stack_no_stack_prot stack.c"

gcc -z execstack -o stack_dash_no_stack_prot stack_dash.c
echo "gcc -z execstack -z -o stack_dash_no_stack_prot stack_dash.c"



# --== no execstack ==--
gcc -fno-stack-protector -o stack_no_execstack stack.c
echo "gcc -fno-stack-protector -o stack stack.c"

gcc -fno-stack-protector -o stack_dash_no_execstack stack_dash.c
echo "gcc -fno-stack-protector -o stack_dash stack_dash.c"


gcc exploit.c -o exploit
echo "gcc exploit.c -o exploit"

gcc exploit_dash.c -o exploit_dash
echo "gcc exploit_dash.c -o exploit_dash"
# gcc dash_shell_test.c -o dash_shell_test
# echo "gcc dash_shell_test.c -o dash_shell_test"

# gcc -z execstack -z norelro -fno-stack-protector -o stack_dash -O0 -m32 -no-pie stack_dash.c
# echo "gcc -z execstack -z norelro -fno-stack-protector -o stack_dash -O0 -m32 -no-pie stack_dash.c"
# gcc exploit_dash.c -o exploit_dash
# echo "gcc exploit_dash.c -o exploit_dash"

sudo chown root dash_shell_test
echo "sudo chown root dash_shell_test"
sudo chmod 4755 dash_shell_test
echo "sudo chmod 4755 dash_shell_test"

sudo chown root stack
echo "sudo chown root stack"
sudo chmod 4755 stack
echo "sudo chmod 4755 stack"
sudo chown root stack_dash
echo "sudo chown root stack_dash"
sudo chmod 4755 stack_dash
echo "sudo chmod 4755 stack_dash"
./exploit
./exploit_dash
