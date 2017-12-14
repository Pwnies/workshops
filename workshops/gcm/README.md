# GCM; The illegal attack

Secrecy of data is not enough.
If an adversary is allowed to modify the ciphertext
undetected during transport the system is often completely
broken in practice.
To mitigate this an auxiliary "tag" can be added to the ciphertext;
a so called MAC (Message Authentication Code).
The encryption process and MAC generation combined constitutes an authenticated encryption scheme.

GCM is among the most widely deployed modes of
operations for authenticated encryption:

As of 2017, 71.2% TLS of connections to [Cloudflare](https://blog.cloudflare.com/aes-cbc-going-the-way-of-the-dodo) used AES-GCM.

The AES-GCM construction is very simple and provides high speed encryption &
authentication with hardware support on many architectures.
However, the security (proof) of AES-GCM relies crucially on the assumption
that we can reliably choose a new nonce with every encryption,
an assumption which is often violated in practice...

This leads to a total break.

# Preparation

For this attack we will rely on a system called SageMath (FOSS) to manipulate algebraic structures.
SageMath can be downloaded [here](https://www.sagemath.org/),
however there is also an online interactive shell at [CoCalc](https://cocalc.com/) which is sufficient for our purposes.

Please sign up for CoCalc or install SageMath, either by downloading from [sagemath.org](http://www.sagemath.org/) or by using docker:

> docker pull sagemath/sagemath
