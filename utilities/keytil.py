import os
from Crypto.PublicKey import RSA
from Crypto import Random
from base64 import b64encode, b64decode
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad
# from Crypto.Util.Padding import unpad
import base64

class Keytil:
    def __init__(self) -> None:
        pass
    
    @staticmethod
    def rsa_encrypt(plainData, crypt_key):
        key = b64decode(crypt_key)
        key = RSA.importKey(key)
        
        cipher = PKCS1_OAEP.new(key)
        ciphertext = b64encode(cipher.encrypt(bytes(plainData, "utf-8")))
        return ciphertext
    
    @staticmethod
    def aes_decrypt(ciphertext, key):
        unpad = lambda s : s[:-ord(s[len(s)-1:])]
        enc = b64decode(ciphertext)
        iv = enc[:16]
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))

    @staticmethod
    def aes_encrypt(raw, key):
        BS = 32
        pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    @staticmethod
    def rsa_decrypt(cipherData, crypt_key):
        key = b64decode(crypt_key)
        key = RSA.importKey(key)

        cipher = PKCS1_OAEP.new(key)
        plaintext = cipher.decrypt(b64decode(cipherData))
        return plaintext
    
    @staticmethod
    def encrypt_response(responseData: str, cryptKey):
        return Keytil.rsa_encrypt(responseData, cryptKey).decode('utf-8')
    
    def generate_key_pairs(self, username, password, key_length = 2048):
        key = RSA.generate(key_length)
        private_key = key.export_key('PEM')
        public_key = key.publickey().exportKey('PEM')
        # message = input('plain text for RSA encryption and decryption:')
        # message = str.encode(message)

        # rsa_public_key = RSA.importKey(public_key)
        # rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
        # encrypted_text = rsa_public_key.encrypt(message)
        # #encrypted_text = b64encode(encrypted_text)

        # print('your encrypted_text is : {}'.format(encrypted_text))


        # rsa_private_key = RSA.importKey(private_key)
        # rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
        # decrypted_text = rsa_private_key.decrypt(encrypted_text)

        # print('your decrypted_text is : {}'.format(decrypted_text))
        
        os.makedirs(f"keys/{username}/", exist_ok=True)
        private_key_file = open(f"keys/{username}/private-key.pem", "w")
        private_key_file.write(private_key.decode())
        private_key_file.close()

        public_key_file = open(f"keys/{username}/public-key.pub", "w")
        public_key_file.write(public_key.decode())
        public_key_file.close()