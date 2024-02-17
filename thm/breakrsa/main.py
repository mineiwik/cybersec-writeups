from Cryptodome.PublicKey import RSA
from gmpy2 import isqrt_rem
from math import lcm

def fermat_factor(n):
    if (n % 2) == 0:
        return (n/2, 2)
    
    a, rem = isqrt_rem(n)
    b = 0

    while rem > 0:
        a = a + 1
        b2 = a * a - n
        b, rem = isqrt_rem(b2)
    
    return (a + b, a - b)

def get_public_key(path):
    f = open(path, "r")
    public_key = RSA.import_key(f.read())
    f.close()
    return public_key

def pwn():
    public_key = get_public_key("id_rsa.pub")

    n = public_key.n
    e = public_key.e

    p, q = fermat_factor(n)

    d = pow(public_key.e, -1, lcm(p-1, q-1))

    private_key = RSA.construct((n, e, d))

    with open("id_rsa", "wb") as f :
        f.write(private_key.export_key())

    print("\033[95m###########\033[0m")
    print("\033[95m# RSA PWN #\033[0m")
    print("\033[95m###########\033[0m")    

    print("\033[94mn:\033[0m", n)
    print("\033[94me:\033[0m", e)
    print("\033[94mp:\033[0m", p)
    print("\033[94mq:\033[0m", q)
    print("\033[94md:\033[0m", d)
    print("\033[94mDiff between p & q:\033[0m", p-q)
    print("\033[92mPrivate key has been successfully exported to the file \033[4mid_rsa\033[0m")


if __name__ == "__main__":
    pwn()