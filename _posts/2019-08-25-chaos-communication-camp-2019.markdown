---
title:  "Chaos Communication Camp 2019"
date:   2019-08-25
categories: [writeup]
tags: [writeups, crypto]
---
*Author: hyperreality*

## Prejudiced Randomness 1

> I found new uber crypto that allows us to securely generate random numbers!
> Lets use this to play a very fair game of random chance!
> If you manage to win 90% of games, I'll give you a flag!
> Tell you what, I'll even give you one if you manage to lose 90%!

This challenge involves playing a game against the remote server, with 42 rounds. In each round:
 - We send $$n$$, a composite of two large primes, $$p$$ and $$q$$.
 - The server generates a random integer $$r \in [0, n]$$, It then finds $$s = r^2 \mod n$$ and sends us $$s$$.
 - We must send a value for $$r$$, which we'll call $$r_g$$, to the server. The server validates that $$r_g$$ is indeed a root of $$s$$.
 - The server calculates $$gcd(\lvert r-r_g \rvert, n)$$.
     - If it is able to factorise $$n$$ into the primes $$p$$ and $$q$$, the server wins.
     - If it is unable to calculate the primes, we win.
 - Finally, we send the primes $$p$$ and $$q$$ to the server, and it checks that they are valid 512-bit or more primes using a variant of the [Miller-Rabin primality test](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test).

```python
for i in range(games):
    while True:
        n = int(raw_input("Give me a fresh composite n=p*q\n> "))
        for p in seen_p:
            if n % p == 0:
                print "I already know a prime factor! Use a different n: ", p
                break
        else:
            break

    r = R.randint(0, n)
    s = r*r % n
    print "Alrighty, now please give me the root of\n%d" % s
    ans = int(raw_input("> "))
    if (ans * ans) % n != s:
        print "This is wrong. I wont play with cheaters. Bye!"
        sys.exit()

    p = gcd(n, (r-ans) % n)
    q = n / p

    if p>1 and q>1:
        print "RESULT: I won! Here are your factors: ", p, q
    else:
        print "RESULT: Hrmpf you win."
        wins += 1
```

This is essentially a [Rabin cryptosystem](https://en.wikipedia.org/wiki/Rabin_cryptosystem), which is like a simplified form of [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)), using $$e=2$$ and the factorisation of $$n = p \times q$$ directly as the private key. Rabin, unlike RSA, has been proven to be as hard to solve as integer factorisation, however it has several practical difficulties which has contributed to its lack of popularity compared to RSA.

The largest of these practical difficulties is exploited in this challenge. Because decrypting a Rabin ciphertext is just finding its modular square root (which is of course easy if you know the factorisation of the modulus $$n$$) there are actually four roots/possible plaintexts which could produce each ciphertext.

While one of these roots is the original plaintext, the other three are garbage, and they open the door to a dangerous attack. The roots may be divided into two sets, $$(r_0, r_1)$$, $$(r_2, r_3)$$. If you know a root from each of the sets, you can trivially figure out the factorisation of $$n$$. For some reason this issue isn't described in the most recent version of the Wikipedia article, so [here is a link](https://en.wikipedia.org/w/index.php?title=Rabin_cryptosystem&oldid=604553404#Decryption) to an older revision, and it's also noted in Rabin's [original paper](http://publications.csail.mit.edu/lcs/pubs/pdf/MIT-LCS-TR-212.pdf).

When the server sends us $$s$$ and we have to send back $$r_g$$, there is a 50% chance that $$r_g$$ will be in a different set to the $$r$$ that the server selected, and thus a 50% chance that $$gcd(\lvert r-r_g \rvert, n)$$ will successfully give the server $$p$$ and $$q$$. So it will win roughly 50% of the time.

But to win the easy flag, we have to win over 90% of the time, and to win the hard flag, less than 10% of the time.

An idea we had was to set $$p = q$$ when generating $$n$$. This essentially breaks the Rabin cryptosystem, which relies on the isomorphism between $$\mathbf{Z}_{pq}$$ and $$\mathbf{Z}_{p} \times \mathbf{Z}_{q}$$, which only holds when $$p \ne q$$. Then, while we can still calculate the root $$r$$ using a different method, the server's method for calculating $$p$$ will no longer work, as there are no longer four roots.

We can use the [Tonelli-Shanks algorithm](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm) to solve the square root of $$s$$ modulo the prime $$p$$:

$$r^2 \equiv s \mod p$$

And then use [Hensel's lifting lemma](https://en.wikipedia.org/wiki/Hensel's_lemma) to "lift" this solution to a higher power of $$p$$:

$$r^2 \equiv s \mod p^2$$

Which is the same as finding the square root of $$s \mod n$$, and allows us to win against the server every time.

```python
from pwn import *
from Crypto.Util import number


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)


# Source:
# https://github.com/p4-team/crypto-commons/blob/893bc4ff2601ba36c4e2b0cf8c89239f7839a050/crypto_commons/rsa/rsa_commons.py#L194
def lift(f, df, p, k, previous):
    result = []
    for lower_solution in previous:
        dfr = df(lower_solution)
        fr = f(lower_solution)
        if dfr % p != 0:
            t = (-(egcd(dfr, p)[1]) * int(fr / p ** (k - 1))) % p
            result.append(lower_solution + t * p ** (k - 1))
        if dfr % p == 0:
            if fr % p ** k == 0:
                for t in range(0, p):
                    result.append(lower_solution + t * p ** (k - 1))
    return result


# Source:
# https://github.com/p4-team/crypto-commons/blob/893bc4ff2601ba36c4e2b0cf8c89239f7839a050/crypto_commons/rsa/rsa_commons.py#L209
def hensel_lifting(f, df, p, k, base_solution):
    """
    Calculate solutions to f(x) = 0 mod p^k for prime p
    :param f: function
    :param df: derivative
    :param p: prime
    :param k: power
    :param base_solution: solution to return for p=1
    :return: possible solutions to f(x) = 0 mod p^k
    """
    if type(base_solution) is list:
        solution = base_solution
    else:
        solution = [base_solution]
    for i in range(2, k + 1):
        solution = lift(f, df, p, i, solution)
    return solution


# Source: https://codereview.stackexchange.com/q/43210
def legendre_symbol(a, p):
    """
    Legendre symbol
    Define if a is a quadratic residue modulo odd prime
    http://en.wikipedia.org/wiki/Legendre_symbol
    """
    ls = pow(a, (p - 1)/2, p)
    if ls == p - 1:
        return -1
    return ls


# Source: https://codereview.stackexchange.com/q/43210
def prime_mod_sqrt(a, p):
    """
    Square root modulo prime number
    Solve the equation
        x^2 = a mod p
    and return list of x solution
    http://en.wikipedia.org/wiki/Tonelli-Shanks_algorithm
    """
    a %= p

    # Simple case
    if a == 0:
        return [0]
    if p == 2:
        return [a]

    # Check solution existence on odd prime
    if legendre_symbol(a, p) != 1:
        return []

    # Simple case
    if p % 4 == 3:
        x = pow(a, (p + 1)/4, p)
        return [x, p-x]

    # Factor p-1 on the form q * 2^s (with Q odd)
    q, s = p - 1, 0
    while q % 2 == 0:
        s += 1
        q //= 2

    # Select a z which is a quadratic non resudue modulo p
    z = 1
    while legendre_symbol(z, p) != -1:
        z += 1
    c = pow(z, q, p)

    # Search for a solution
    x = pow(a, (q + 1)/2, p)
    t = pow(a, q, p)
    m = s
    while t != 1:
        # Find the lowest i such that t^(2^i) = 1
        i, e = 0, 2
        for i in xrange(1, m):
            if pow(t, e, p) == 1:
                break
            e *= 2

        # Update next value to iterate
        b = pow(c, 2**(m - i - 1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i

    return [x, p-x]


def get_root(a, p):
    ts = prime_mod_sqrt(a, p)

    f = lambda x: x**2 - a
    df = lambda x: 2 * x
    k = 2
    base = ts[0]
    lifted = hensel_lifting(f, df, p, k, base)
    return lifted[0]


r = remote("hax.allesctf.net", 7331)

print(r.recvuntil("90%!"))

while True:
    print(r.recvline())
    print(r.recvline())

    p = 0
    while not p % 4 == 3:
        p = number.getPrime(512)
    n = p * p

    r.sendline(str(n))
    print(r.recvline())
    s = int(r.recvline())

    ans = get_root(s, p)
    print(ans)

    r.sendline(str(ans))
    print(r.recvline())
    print(r.recvline())

    r.sendline(str(p))
    r.sendline(str(p))
```


## Prejudiced Randomness 2

Unfortunately we weren't able to figure out how to get the hard flag. We would love to see a writeup for it.


## Power

> RSA is too boring. Raise to the power of x instead.

After calculating large prime $$p$$, we have to find $$x$$ such that:

$$a \equiv x^x \mod p$$

Where $$a$$ is a challenge $$a \in [1, p-1]$$.

The maths are explained in this [excellent writeup](https://github.com/wonrzrzeczny/CTF-writeups/blob/master/Chaos%20Communication%20Camp%202019%20CTF/Power/readme.md), here is our implementation:

```python
from pwn import *
from fractions import gcd

def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
 
    for n_i, a_i in zip(n, a):
        p = prod / n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod
 
 
def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a / b
        a, b = b, a%b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1
 

def get_resp(base):
    line = r.recvline()
    print(line)
    chal = line.split()[1]
    print(r.recvuntil(': '))
    r.sendline(str(base))
    line = r.recvline()
    resp = line.split()[1]

    return int(chal), int(resp)

r = remote('hax.allesctf.net', 1337)

N1 = 142
N2 = 143 # first x which wraps the modulus

chal1, resp1 = get_resp(N1)
chal2, resp2 = get_resp(N2)
d1 = N1 ** N1 - resp1
d2 = N2 ** N2 - resp2

p = gcd(d1,d2)
print("modulus: %s" % p)


line = r.recvline()
print(line)
chal = int(line.split()[1])
print(r.recvuntil(': '))

n = [p, p-1]
a = [chal, 1]

ans = chinese_remainder(n, a)

r.sendline(str(ans))
line = r.recvline()
print(line)
line = r.recvline()
print(line)

r.close()
```

