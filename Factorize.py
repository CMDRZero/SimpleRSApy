from math import gcd, exp, log, ceil
import WeakRSA as rsa
import datetime
from sympy import Matrix
time = datetime.datetime

def Crack(n, func):
    p = func(n)
    q = n // p
    return p,q

def Rho(n):
    g = lambda x:(x**2+1)%n 
    start = 2
    while True:
        y = x = start
        d = 1
        while d == 1:
            x = g(x)
            y = g(g(y))
            d = gcd(abs(x-y), n)
        if d == n:
            start += 1
            continue
        return d

def PrimesUpto(n):
    maxprime = n
    numbs = list(range(2, maxprime+1))
    primes = []
    while numbs != []:
        n = numbs[0]
        del numbs[0]
        for k in range(n**2, maxprime+1, n):
            if k in numbs:
                numbs.remove(k)
        primes.append(n)
    return primes

def EulerCrit(a, p):
    return pow(a, (p-1)//2, p) == 1

def QS(n):
    B = int(exp( (.5+.01) * ( log(n) * log(log(n)) )**.5 ))
    factors = [p for p in PrimesUpto(B) if EulerCrit(n, p)]
    csqrtn = ceil(n**.5)
    ary = []
    sq = []
    for i in range(1000000 * len(factors)):
        qn = (csqrtn + i)**2-n
        qn0 = qn
        ist = [0]*len(factors)
        for j, p in enumerate(factors):
            while qn % p == 0:
                ist[j] ^= 1
                qn //= p
        if qn == 1:
            ary.append(ist)
            sq.append(qn0)
            if len(sq) == len(factors):
                break
    else:
        assert False, f'Failure'

    ary = Matrix(ary).transpose()
    inv = ary.nullspace()
    return inv
            
def TestCrack(func):
    pvt, pub = rsa.AutoKeys()
    E, n = pub
    D, _ = pvt
    print(f'Attempting to crack: `{n}`')
    then = time.now()
    p, q = Crack(n, func)
    now = time.now()
    dt = now-then
    print(f'Took {dt}')
    Dq = rsa.PrivateKey(p, q, E)[0]
    print(f'Found D to be `{Dq}` and was `{D}` which was '+['incorrect', 'correct'][D==Dq])
