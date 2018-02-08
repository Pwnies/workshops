#include "code.c"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/mman.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>

void decipher(uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    unsigned int num_rounds = 32;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}

int main(int argc, char** argv) {
    if (argc != 2)
        return -1;

    // guess a key

    uint32_t key[4] = {0, 0, 0, 0};
    uint32_t head[2];

    do {
        head[0] = ((uint32_t*) code)[0];
        head[1] = ((uint32_t*) code)[1];
        decipher(head, key);
        if (head[0] == 0 && head[1] == 0)
            break;
    } while (++key[3] < (1 << 24));

    // decrypt code

    uint32_t* exec = (uint32_t*) code;
    uint32_t *sandbox = (uint32_t*) mmap(
        0x0,
        sizeof(code),
        PROT_WRITE | PROT_READ | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        0,
        0
    );

    uint32_t *dst = sandbox;
    for (size_t n = 0; n < sizeof(code); n += 8) {
        decipher(exec, key);
        (*dst++) = (*exec++);
        (*dst++) = (*exec++);
    }

    // check flag

    int ret = ((int (*)(char*)) (sandbox + 2))(argv[1]);
    if (ret) {
        printf("nice flag\n");
    } else {
        printf("bad flag\n");
    }
}
