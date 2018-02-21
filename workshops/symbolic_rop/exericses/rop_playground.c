#include <stdlib.h>
#include <stdio.h>

void foo(int a){
    printf("foo(%d)\n", a);
}

void bar(int a, int b){
    printf("bar(%d, %d)\n", a, b);
}

void baz(int a, int b, int c){
    printf("foo(%d, %d, %d)\n", a, b, c);
}

int main(int argc, char **argv){
    char line[16]; // buffer way too small for gets!

    system("echo Give me some rop!");
    system("echo Try to call foo, bar and baz with some arguments");
    system("echo or pop a shell using system and gets");
    system("echo good luck!");

    gets(line); // stack overflow right here, see man 3 gets.

    printf("%s, that is some nice rop!", line);

    return 0;
}
