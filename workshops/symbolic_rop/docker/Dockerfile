FROM debian:stretch

ARG USER=ken

RUN dpkg --add-architecture armhf
RUN dpkg --add-architecture i386

RUN apt-get update -y
RUN apt-get install -y gcc git python python-pip python-z3 libcapstone3 sudo ipython curl qemu-user-static qemu-user
RUN apt-get install -y gcc-6-arm-linux-gnueabihf libc6:armhf libc6:i386 gcc-6-multilib libc6-dev-x32 build-essential gcc-arm-linux-gnueabihf

# user setup

RUN adduser --disabled-password --gecos '' ${USER}
RUN adduser ${USER} sudo
RUN usermod -m -d /home/${USER} ${USER}
RUN chsh -s /bin/bash ${USER}
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER ${USER}
WORKDIR /home/${USER}

COPY solve_sudoku.py .
COPY rop_playground.c .
COPY Makefile .

# pwndbg

RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# pwntools

RUN git clone https://github.com/Gallopsled/pwntools
RUN sudo pip2 install -e pwntools

# universal rop

RUN git clone https://github.com/kokjo/universalrop.git
ENV PYTHONPATH=/home/${USER}/universalrop

