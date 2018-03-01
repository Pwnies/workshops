#!/bin/bash
SCRIPT=$(readlink -f $0)
SCRIPTPATH=$(dirname $SCRIPT)

docker build -t hackenv . && docker run --cap-add=SYS_PTRACE --security-opt=apparmor:unconfined --privileged -v $SCRIPTPATH/..:/workshop -it hackenv bash
