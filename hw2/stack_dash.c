/* stack.c */
/* This program has a buffer overflow vulnerability. */
/* Our task is to exploit this vulnerability */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int bof(char *str)
{
    char buffer[18];
    /* The following statement has a buffer overflow problem */
    strcpy(buffer, str);
    register int i asm("esp"); //add this line 
    printf("$esp in stack = %#010x\n", i); // and this line will print esp
}

int main(int argc, char **argv)
{
    char str[517];
    FILE *badfile_dash;
    badfile_dash = fopen("badfile_dash", "r");
    fread(str, sizeof(char), 517, badfile_dash);
    
    bof(str);
    printf("Returned Properly\n");
    return 1;
}
