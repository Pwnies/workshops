FROM debian:testing

ARG USER=ken

RUN apt-get update -y
RUN apt-get install -y gcc git python python-pip
RUN apt-get install -y neovim sudo ipython curl

# radare

RUN git clone https://github.com/radare/radare2
RUN cd radare2 && sys/install.sh
RUN pip2 install r2pipe

# pwntools

RUN git clone https://github.com/Gallopsled/pwntools
RUN pip2 install -e pwntools

# angr

RUN pip2 install angr

# user account

RUN adduser --disabled-password --gecos '' ${USER}
RUN adduser ${USER} sudo
RUN usermod -m -d /home/${USER} ${USER}
RUN chsh -s /bin/bash ${USER}
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER ${USER}

RUN cd /home/${USER} && git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
RUN cd /home/${USER} && git clone https://github.com/gast04/r4ge

COPY radare2rc /home/${USER}/.radare2rc
COPY init.vim /home/${USER}/.config/nvim/init.vim
