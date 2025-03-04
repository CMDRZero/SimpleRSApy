import random
from math import log2
import hashlib

log = lambda x: int(log2(x))

gBitsInKey = 256
gEncLen = 200
gStdE = 1 << 16 | 1
gZ85 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#'

gHalfKey = gBitsInKey // 2

def MillerRabin(n, k=10):
    s = log((n-1)&(1-n))
    if not s:
        return False
    d = (n-1) >> s
    for _ in range(k):
        b = random.randint(2, n-2)
        x = pow(b, d, n)
        for _ in range(s):
            y = pow(x, 2, n)
            if y == 1 and x != 1 and x != n-1:
                return False
            x = y
        if y != 1:
            return False
    return True

def PQisSecure(p, q):
##    n = p * q
##    if abs(p-q) < 2 * n**.25:
##        return False
##    dMaybe = PrivateKey(p, q, gStdE)[0]
##    if dMaybe < n**.25 / 3:
##        return False
##    if n < 1<<gEncLen:
##        return False
    return True

def GenerateRawPQ():
    rand = 4
    while not IsPrime(rand):
        rand = random.randint(1, 1<<gHalfKey)
    p = rand

    rand = 4
    while not IsPrime(rand):
        rand = random.randint(1, 1<<gHalfKey)
    q = rand
    return p, q

def GeneratePQ():
    while True:
        p, q = GenerateRawPQ()
        if PQisSecure(p, q):
            break
        print(f'Insecure pq generated')
    return p, q

def IsPrime(n, k = 10):
    if n < 1_000_000_000:
        return DetrIsPrime(n)
    else:
        return MillerRabin(n, k=k)

def DetrIsPrime(n):
    for i in range(2,int(n**.5)+1):
        if n % i == 0:
            return False
    return True

def SmallestFactor(n):
    for i in range(2,int(n**.5)):
        if n % i == 0:
            return i
    return None

def PrivateKey(p, q, E):
    return (pow(E, -1, (p-1)*(q-1)), p*q)
def PublicKey(p, q, E):
    return (E, p*q)
def Keys(p, q, E):
    return (PrivateKey(p, q, E), PublicKey(p, q, E))
def AutoKeys():
    p, q = GeneratePQ()
    E = gStdE
    return Keys(p, q, E)
def FmtKeys(pvt, pub):
    print(f'\tPrivate Key (DO NOT SHARE!): \n{KeyStr(pvt)}')
    print(f'\tPublic Key: \n{KeyStr(pub)}')
    

def Apply(key, msg):
    P, n = key if type(key) != str else SepKeyStr(key)
    return pow(msg, P, n)

def Pad(msg):
    return msg
    lenmsg = 1+log(msg)
    assert lenmsg <= gEncLen // 2, f'Message has bit length `{lenmsg}`, but should not exceed `{gEncLen // 2}`'
    lenlenmsg = log(gBitsInKey) #bits allocated to len of message length
    rb = gEncLen - lenmsg - lenlenmsg #Remaining bits
    pmsg = (random.randint(0,1<<rb) << lenmsg | msg) << lenlenmsg | lenmsg
    return pmsg

def DePad(pmsg):
    lenlenmsg = log(gBitsInKey) #bits allocated to len of message length
    lenmsg = pmsg % (1<<lenlenmsg)
    msg = (pmsg >> lenlenmsg) % (1<<lenmsg)
    return msg
    
def Enc85(n):
    o = ''
    while n:
        r = n % (1<<(8*4))
        n = n >> (8 * 4)
        for _ in range(5):
            o += gZ85[r % 85]
            r //= 85
    return o[::-1]
def Dec85(m):
    m = m.zfill(5*-(-len(m)//5))[::-1]
    v = 0
    p = 1
    for i in range(len(m)//5):
        b = m[5*i:][:5]
        for j in range(5):
            v += gZ85.index(b[j]) * 85**j * p
        p *= 256**4
    return v

def KeyStr(i):
    return '`'.join([Enc85(x) for x in i])
def SepKeyStr(x):
    return [Dec85(y) for y in x.split('`')]

def Encrypt(pubKey, msg):
    return Enc85(Apply(pubKey, Pad(msg)))
def Decrypt(pvtKey, msg):
    return DePad(Apply(pvtKey, Dec85(msg)))

def SignMsg(pvtKey, msg):
    h = int(hashlib.sha256(msg.encode('utf-8')).hexdigest(), 16)
    return (msg, Encrypt(pvtKey, h))
def VerifySign(pubKey, msg, sign):
    h = int(hashlib.sha256(msg.encode('utf-8')).hexdigest(), 16)
    dh = Decrypt(pubKey, sign)
    return h == dh
