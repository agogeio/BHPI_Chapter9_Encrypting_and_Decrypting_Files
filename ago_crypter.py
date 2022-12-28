import base64
import zlib

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA 
from Cryptodome.Random import get_random_bytes
from io import BytesIO

PRI_KEY_LOC = './keys/key.pri'
PUB_KEY_LOC = './keys/key.pub'

def generate_write():
    rsa_key = RSA.generate(2048)
    print(rsa_key)

    private_key = rsa_key.export_key()
    public_key = rsa_key.public_key().exportKey()

    with open(PRI_KEY_LOC, 'wb') as f_pri:
        f_pri.write(private_key)

    with open(PUB_KEY_LOC, 'wb') as f_pub:
        f_pub.write(public_key)

def get_rsa_keys(keytype):
    if keytype == 'pri':
        with open(PRI_KEY_LOC) as f:
            key = f.read()
    elif keytype == 'pub':
        with open(PUB_KEY_LOC) as f:
            key = f.read()
    else:
        print(f'Invalid key type')

    rsakey = RSA.importKey(key)
    return (PKCS1_OAEP.new(rsakey), rsakey.size_in_bytes())



if __name__ == '__main__':
    generate_write()