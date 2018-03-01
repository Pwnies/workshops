CFLAGS=-no-pie -fno-stack-protector

all: rop_playground.amd64 rop_playground.x86 rop_playground.arm

rop_playground.amd64: rop_playground.c
	gcc ${CFLAGS} -o $@ rop_playground.c

rop_playground.x86: rop_playground.c
	gcc -m32 ${CFLAGS} -o $@ rop_playground.c

rop_playground.arm: rop_playground.c
	arm-linux-gnueabihf-gcc ${CFLAGS} -o $@ rop_playground.c
	
clean:
	rm -f rop_playground.amd64 rop_playground.x86 rop_playground.arm
