---
title:  "0CTF/TCTF 2020 Finals: Oblivious (crypto)"
date:   2020-09-26
categories: [writeup]
tags: [writeups, crypto]
authors: ["Holocircuit", "esrever (polygl0ts)", "v01d"]
---

## Oblivious

In this challenge we are given the code for a server running some kind of RSA-based algorithm.

```python
class Task(SocketServer.BaseRequestHandler):
    def genkey(self):
        '''
        NOTICE: In remote server this key is generated like below but hardcoded, since genkey is time/resource consuming
        and I don't want to add annoying PoW, especially for a final event.
        This function is kept for your local testing.
        '''
        p = getStrongPrime(BITS/2)
        q = getStrongPrime(BITS/2)
        self.p = p
        self.q = q
        self.n = p*q
        self.e = 0x10001
        self.d = inverse(self.e, (p-1)*(q-1))

    def genmsg(self):
        ...

    def recvn(self, sz):
        ...

    def handle(self):
        # Obligatory solvers' comment: we could probably break the Mersenne with enough perseverance. But what fun is that?
        seed(os.urandom(0x20))
        self.genkey()
        self.request.sendall("n = %d\ne = %d\n" % (self.n, self.e))
        try:
            while True:
                self.request.sendall("--------\n")
                m0, m1 = self.genmsg()
                x0 = randint(1, self.n-1)
                x1 = randint(1, self.n-1)
                self.request.sendall("x0 = %d\nx1 = %d\n" % (x0, x1))
                v = int(self.recvn(BITS/3))
                k0 = pow(v^x0, self.d, self.n)
                k1 = pow(v^x1, self.d, self.n)
                self.request.sendall("m0p = %d\nm1p = %d\n" % (m0^k0, m1^k1))
        finally:
            self.request.close()
```

A bit of investigation and the title point us towards [1-2 Oblivious Transfer](https://en.wikipedia.org/wiki/Oblivious_transfer#1%E2%80%932_oblivious_transfer), which is indeed what is implemented on the server almost verbatim (so we'll call the server Alice). There are, however, some differences. For one, XOR is used instead of addition/subtraction. This helps because of its self-inverse property, but the challenge could _probably_ also be solved if implemented with standard arithmetic. More importantly, the messages which Alice obliviously sends us are not just any old pair of numbers:

```python
def genmsg(self):
    '''
    simply xor looks not safe enough. what if we mix adjacent columns?
    '''
    m0 = randint(1, self.n-1)
    m0r = (((m0&1)<<(BITS-1)) | (m0>>1))
    m1 = m0^m0r^flagnum
    return m0, m1
```

So $$m_0 \in [1,n)$$, fair enough. But $$m_1 = m_0 \oplus ROR(m_0) \oplus flag$$, where $$ROR$$ is $$2048$$-bit right-rotate. This relationship is ultimately what will allow us to solve the challenge, but let's first make some preliminary observations.

Simply by virtue of how 1-2 OT normally works, we can obtain some information. Let $$D: \{0,1\}^{2048} \to \{0,1\}^{2048}$$ denote RSA decryption with Alice's private key. Consider what we get back by sending $$v = x_0$$:

- $$m_0' = m_0 \oplus D(v \oplus x_0) = m_0 \oplus D(0) = m_0$$
- $$m_1' = m_1 \oplus D(v \oplus x_1) = m_0 \oplus ROR(m_0) \oplus flag \oplus D(x_0 \oplus x_1)$$

Now knowing $$m_0$$ and the unusual relationship between messages, we can calculate $$m_1' \oplus m_0 \oplus ROR(m_0) = flag \oplus D(x_0 \oplus x_1)$$. For all intents and purposes $$x_0 \oplus x_1$$ is random, so our only avenue at this point is to try to decrypt it somehow. And as it turns out, we can! But this took quite a while to figure out.

One important criterion in pruning the search space was: "can our solution break vanilla 1-2 OT or RSA?". If it could, that's probably not the way to go. After rejecting several attempts in this way, we realized that there is a subtle property of all $$m_1'$$s which can be exploited.

You see, for any number $$x$$, $$x \oplus ROR(x)$$ has an even popcount (number of set bits). "_So what?_", you might ask. Well, this turns out to be sufficient for us to construct a single-bit adaptive chosen-ciphertext RSA oracle and apply the [Bleichenbacher attack](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf) to compute $$D$$. Let's look at what we mean by this.

Write $$m_1'(i, v)$$ to mean the value of $$m_1'$$ obtained from Alice in the $$i$$-th exchange given our input $$v$$, $$m_0(i)$$ to mean the random message for that round, and $$x_b(i)$$ for the nonces.

Now consider the popcount of $$m_1'(i, x_1(i) \oplus y)$$. In particular, consider its parity - let $$pp(x)$$ mean the _popcount parity_ of $$x$$. We have
$$pp(m_1'(i, x_1(i) \oplus y)) = pp(m_0(i) \oplus ROR(m_0(i)) \oplus flag \oplus D(y)) = pp(flag \oplus D(y))$$ where the last equality follows since $$pp$$ distributes over $$\oplus$$. Observe, $$flag$$ is a constant. So the whole expression depends _only on $$pp(D(y))$$_.  In particular, it does not depend on any of $$m_0(i), x_b(i)$$ - we have eliminated per-round randomness!

The final piece of the puzzle is how to construct an oracle out of this. Consider, for any $$y$$, $$pp(D(y))$$ and $$pp(D(y\cdot2^e))$$. Well, $$D(y) < n$$ by definition, so $$D(y\cdot2^e) \equiv 2D(y) \pmod n$$ might be less or more than $$n$$ over $$\mathbb{Z}$$. If it's less, then it wouldn't have wrapped around modulo $$n$$ and so its popcount parity would equal $$pp(D(y))$$. On the other hand if it's more, then the wrapping around $$n$$ _might_ cause the popcount parity to flip. Overall, this tells us that if $$pp(D(y)) \neq pp(D(y\cdot2^e))$$, then $$2y \geq n$$. Because a wraparound might preserve $$pp$$, the converse is not true - if $$pp(D(y)) = pp(D(y\cdot2^e))$$, we know nothing. And amazingly, despite how weak this primitive is, it still allows us to carry out a Bleichenbacher attack and compute $$D$$!

So in the end, we do just that and use it to obtain the flag from information we received in the first exchange. The attack more or less follows the original '98 formulation, querying the oracle on $$D(y \cdot s^e \cdot 2^e)$$ for increasing values of $$s$$. Because the oracle should provide both a lower and upper bound, ours has a little twist where we also try $$D(-y \cdot s^e \cdot 2^e)$$ in order to obtain the upper. Our solution recovers the flag in roughly 7000 exchanges with Alice.

`flag{Hav3_YoU_reCogn1z3D_tHAt_I_m_uS1Ng_pypy_0n_sErvEr}`
