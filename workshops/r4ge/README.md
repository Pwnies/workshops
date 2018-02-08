# Symbolic execution is all the r4ge

We will be exploring the use of symbol execution and
scripted debuggers/disassembly frameworks (r2) for reverse engineering binary programs.
We will be applying the techniques against an example "crackme".

What we will cover:

- The r2 reversing framework
- An introduction to angr (brief)
- Combining debugging and symbolic execution using the r4ge plugin

What we will not cover:

- How SMT solvers work
- How angr works under-the-hood<sup>TM</sup>
- Exploitation

# How do I get the software?

You must be running Linux on x86_64 (in a VM or bare metal) to attend this workshop.
We will requiring the following software for the workshop:

- [angr](https://github.com/angr/angr)
- [r4ge](https://github.com/gast04/r4ge)
- [r2](http://rada.re/r/down.html)
- [r2pipe](https://github.com/radare/radare2-r2pipe)
- python2.7

The recommended method is by using the docker image, if you want to keep your system bloat-free.

First install [docker](https://docs.docker.com/install/) if you have not. For the lazy:

```sh
curl -fsSL get.docker.com -o get-docker.sh
# you will totally read this shell file before running it...
sudo sh get-docker.sh
sudo usermod -aG docker your-user
```

To build the docker image:

```sh
git clone https://github.com/Pwnies/workshops
cd workshops/workshops/r4ge/docker
./run.sh # builds docker image and runs an interactive shell
```
