# Introduction to binary exploitation and shellcode

This workshop will look at simple *binary exploitaiton*, i.e. how to make a
binary executable program do something we want in a way it isn't supposed to.

While similar material can be found numerous places in books, courses (e.g.
PCS) and on the internet, this workshop takes a different angle: I will give
an opinionated introduction to the tools and workflows required in order to
discover (simple) vulnerabilites and develop exploits. This means pwntools for
reproducible exploits, GDB and scripting for exploit and shellcode debugging,
and some tips and tricks for common gotchas.

# Preparation

The following tools are going to be used:

* python 2.7
* ipython
* pwntools
* GDB with pwndebug (or PEDA)

On Ubuntu/Debian, this should be installable by running approximately the following commands (not tested!):
```
# Install stuff
sudo apt-get install python-pip ipython gdb
sudo pip install pwntools

# Get pwndebug
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh # Note: this does a lot of stuff, read the file if in doubt.
```
