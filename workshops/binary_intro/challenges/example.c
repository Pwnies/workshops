#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char global_buf[128] = { 0 };

int main(int argc, char *argv[]) {
    char buf[128];

    printf("Give me some input!");
    read(0, buf, 256);
    memcpy(global_buf, buf, 128);

    printf("You gave me %zd characters!", strlen(buf));

    return 0;
}
