from hashlib import sha512
import os
import random
import jwt
import datetime
from dotenv import load_dotenv

load_dotenv()

class Security:
    def __init__(self) -> None:
        pass
    
    @staticmethod
    def sha512(data) -> str:
        return sha512(data.encode('utf-8')).hexdigest()
    
    @staticmethod
    def generate_hooger_passphrase(passphrase_length = 6) -> str:
        passphrase_list = open('utilities/passphrase.list', 'r').read().splitlines()
        passphrases = []
        for i in range(passphrase_length):
            passphrases.append(random.choice(passphrase_list))
        return ' '.join(passphrases)
    
    @staticmethod
    def encode_auth_token(jwt_data):
        """
        Generates the JWT Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
                'iat': datetime.datetime.utcnow(),
                'sub': jwt_data
            }
            return jwt.encode(
                payload,
                os.getenv("JWT_SECRET_KEY"),
                algorithm='HS256'
            )
        except Exception as e:
            return e
        
    @staticmethod
    def decode_auth_token(auth_token):
        """
        Decodes the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, os.getenv("JWT_SECRET_KEY"))
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'