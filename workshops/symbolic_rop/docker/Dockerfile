FROM debian:stretch

ARG USER=ken

RUN apt-get update -y
RUN apt-get install -y gcc git python python-pip python-z3 libcapstone3 sudo ipython curl

# user setup

RUN adduser --disabled-password --gecos '' ${USER}
RUN adduser ${USER} sudo
RUN usermod -m -d /home/${USER} ${USER}
RUN chsh -s /bin/bash ${USER}
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER ${USER}
WORKDIR /home/${USER}

# pwndbg

RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# pwntools

RUN git clone https://github.com/Gallopsled/pwntools
RUN sudo pip2 install -e pwntools

# universal rop

RUN git clone https://github.com/kokjo/universalrop.git
ENV PYTHONPATH=/home/${USER}/universalrop

