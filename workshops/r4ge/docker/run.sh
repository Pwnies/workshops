#!/bin/bash

docker build -t hackenv . && docker run --cap-add=SYS_PTRACE --security-opt=apparmor:unconfined --privileged -v `pwd`:/workshop -it hackenv bash
