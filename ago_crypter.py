import base64
import zlib

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA 
from Cryptodome.Random import get_random_bytes
from io import BytesIO

PRI_KEY_LOC = './keys/key.pri'
PUB_KEY_LOC = './keys/key.pub'
ENCRYPTION_TARGET = './encryption_target'


def generate_write_rsa_keys():
    rsa_key = RSA.generate(2048)
    #* Go to Definition - It must be at least 1024, but **2048 is recommended.**
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


def encrypt(plaintext):
    compressed_text = zlib.compress(plaintext)
    session_key = get_random_bytes(32)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)

    #? Match with encrypted session key in decrypt()
    #? print(session_key)
    #? print('')

    #* Go to Definition 
    #* :param key:
    #*     The secret key to use in the symmetric cipher.

    #*     It must be 16, 24 or 32 bytes long (respectively for *AES-128*,
    #*     *AES-192* or *AES-256*).

    #* :param mode:
    #*     The chaining mode to use for encryption or decryption.
    #*     If in doubt, use ``MODE_EAX``.
    cipher_text, tag = cipher_aes.encrypt_and_digest(compressed_text)
    cipher_rsa, _ = get_rsa_keys('pub')
    #? print(cipher_rsa) is a cipher object
    #? Cryptodome.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher object at 0x7fb47501e500
    encrypted_session_key = cipher_rsa.encrypt(session_key)
    msg_payload = encrypted_session_key + cipher_aes.nonce + tag + cipher_text

    #? Definition of nonce for cryptography
    #? https://en.wikipedia.org/wiki/Cryptographic_nonce
    '''
    In cryptography, a nonce is an arbitrary number that can be used just 
    once in a cryptographic communication.[1] It is often a random or pseudo-random 
    number issued in an authentication protocol to ensure that old communications 
    cannot be reused in replay attacks. They can also be useful as ***initialization 
    vectors*** and in cryptographic hash functions.
    '''

    encrypted = base64.encodebytes(msg_payload)
    return encrypted
    

def decrypt(encrypted):
    encrypted_bytes = BytesIO(base64.decodebytes(encrypted))
    cipher_rsa, keysize_in_bytes = get_rsa_keys('pri')

    # print(cipher_rsa)
    # print(keysize_in_bytes)

    encrypted_session_key = encrypted_bytes.read(keysize_in_bytes)
    
    #? Print the below key to proved that it's encrypted 
    #? print(encrypted_session_key)

    nonce = encrypted_bytes.read(16)
    tag = encrypted_bytes.read(16)
    ciphertext = encrypted_bytes.read()

    session_key = cipher_rsa.decrypt(encrypted_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)

    plain_text = zlib.decompress(decrypted)
    return plain_text

if __name__ == '__main__':

    password = input('Type: "Continue" (case sensitive) in order to continue the program: ')

    if password == "Continue":

        print('Continuing cryptographic program')

        # generate_write_rsa_keys()
        # key = get_rsa_keys('pub')
        # print(key)

        cipher_text = encrypt(b'Hello Secret World v2!')
        plain_text = decrypt(cipher_text)
        print(plain_text)
        