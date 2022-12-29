import base64
import os
import zlib

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA 
from Cryptodome.Random import get_random_bytes
from io import BytesIO

PRI_KEY_LOC = './keys/key.pri'
PUB_KEY_LOC = './keys/key.pub'
ENCRYPTION_TARGET = './encryption_target'
# ENCRYPTION_TARGET = '/home/saiello/Documents/agogeio'

file_list = []


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
    encrypted_session_key = encrypted_bytes.read(keysize_in_bytes)
    nonce = encrypted_bytes.read(16)
    tag = encrypted_bytes.read(16)
    ciphertext = encrypted_bytes.read()
    session_key = cipher_rsa.decrypt(encrypted_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)
    plain_text = zlib.decompress(decrypted)
    return plain_text


def search_dir(dir_path, extension):
  # loop through all the files in the directory
    for file in os.listdir(dir_path):
        # create a full path for the file
        file_path = os.path.join(dir_path, file)
        # if the file is a directory, recursively search it
        if os.path.isdir(file_path):
            search_dir(file_path, extension)
            # if the file is a file, print its path
        else:
            if extension == '.*':
                file_list.append(file_path)
            elif file_path.__contains__(extension):
                file_list.append(file_path)
    return file_list


if __name__ == '__main__':

    password = input('Type: "Continue" (case sensitive) in order to continue the program: ')

    if password == "Continue":

        print('Continuing cryptographic program')

        key_gen = input('Do you need to generate new RSA keys? Warning this will overwrite existing RSA keys and could make decrypting encrypted files impossible (yes/no): ')
        encrypt_decrypt = input('Do you wish to "encrypt" or "decrypt" files? (encrypt/decrypt): ')

        if key_gen == 'yes':
            generate_write_rsa_keys()
        elif key_gen == 'no':
            print('You chose not to generate new RSA keys')
        else:
            print('You did not enter a valid answer, no action taken')
        
        if encrypt_decrypt == 'encrypt':
            extension = input('What is the file type you would like to encrypt; example ".txt", ".pptx", or ".*" for all: ')
            print('Indexing files')
            file_list = search_dir(ENCRYPTION_TARGET, extension)
            
            for file in file_list:
                with open(file, 'rb') as f:
                    cipher_file = encrypt(f.read())
                    file_name = f'{file}.enc'
                    with open(file_name, 'wb') as wf:
                        wf.write(cipher_file)

                os.remove(file)

        elif encrypt_decrypt == 'decrypt':
            print('Files with the .enc extension will be searched for and decrypted if possible')
            print('Indexing files')
            file_list = search_dir(ENCRYPTION_TARGET, '.enc')

            for file in file_list:
                with open (file, 'rb') as crypt_file:
                    clear_text_bytes = decrypt(crypt_file.read())
                    restore_name = file.split('.enc')[0]
                    print(restore_name)

                    with open(restore_name, 'wb') as f:
                        f.write(clear_text_bytes)

            clean_up = input('Would you like to remove remaining encrypted file? (y/n): ')
            if clean_up == 'y':
                for file in file_list:
                    os.remove(file)

        else:
            print('You did not enter a valid encrypt / decrypt answer, no action taken')


        # key = get_rsa_keys('pub')
        # print(key)