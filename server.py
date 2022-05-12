import hashlib
from textwrap import indent
import uuid
from flask import Flask, request, jsonify
import random
from colorama import init, Fore, Back, Style
import socket
from numpy import identity
init()
import signal
import sys
from utilities.interrupt_handler import SIGINT_handler
from utilities.db import Database
from uuid import uuid4
from utilities.security import Security
from utilities.keytil import *
from tinydb import Query
from constants.price import *
from dotenv import load_dotenv, set_key, get_key
import os
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager, verify_jwt_in_request
from distutils.util import strtobool
from constants.server import *
import datetime
import time
import base58
from functools import wraps
import ast

parsedRequests = {}

def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def main():
    load_dotenv()
    app = Flask(__name__)
    handler = SIGINT_handler()
    signal.signal(signal.SIGINT, handler.signal_handler)
    db = Database('Hooger-Ledger.json', 'database/')
    app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY')
    jwt = JWTManager(app)
    initilize_server(db)
    initilize_price(db)
    
    @app.route('/api/v1/login', methods=['POST'])
    def login():
        username = request.json['username']
        password = Security.sha512(request.json['password'])
        queryResult = db.query('users', Query().username == username and
        Query().password == password)
        if (len(queryResult) == 0):
            return jsonify({
                'status': 'error',
                'message': 'نام کاربری یا کلمه عبور نادرست است'
            })
        else:
            return jsonify({
                'status': 'success',
                'message': 'ورود موفقیت آمیز بود',
                'token': create_access_token(identity={
                    'user': {
                        'username': username,
                        'user_id': get_account_public_address(queryResult[0]['username'])
                    }    
                }),
                'user': {
                    'username': username,
                    'user_id': get_account_public_address(queryResult[0]['username'])
                }
            }), 200
    
    @jwt_required(optional=False)
    @app.route('/api/v1/buy_coin', methods=['POST'])
    def buy_coin():
        verify_jwt_in_request()
        current_identity = get_jwt_identity()
        if (current_identity):
            global server_public_address
            sender_public_address = get_account_public_address(get_server_account(db)['username'])
            receiver_public_address = request.json['receiver']
            hooger_price = request.json['hooger_price']
            amount = request.json['amount']
            transaction = {
                'ts_id': str(uuid4()).upper(),
                'sender': sender_public_address,
                'receiver': receiver_public_address,
                'hooger_price': hooger_price,
                'amount': amount,
                'ts_time': str(datetime.datetime.now()),
                'ts_timestamp': int(time.time()),
                'ts_type': 'buy_coin'
            }
            db.insert('transactions', transaction)
            db.insertOrUpdate('transactions_history', {'id': 'latest_transtion', 'transaction': transaction})
            set_key(key_to_set='FIRST_PAYMENT_PERFORMED', value_to_set='true', dotenv_path='.env')
            track_hooger_price_change(db, transaction['ts_type'])
            return jsonify({
                'status': 'success',
                'message': 'خرید با موفقیت انجام شد'
            }), 200
        else:
            print(identity)
            return jsonify({
                'status': 'error',
                'message': 'خطایی در اهراز هویت رخ داده است'
            }), 401
            
    @jwt_required(optional=False)
    @app.route('/api/v1/check_jwt_token', methods=['POST'])
    def check_jwt_token():
        verify_jwt_in_request()
        current_identity = get_jwt_identity()
        if (current_identity):
            return jsonify({
                'status': 'success',
                'message': 'اعتبار سنجی با موفقیت انجام شد'
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'اعتبار سنجی با خطا مواجه شد'
            }), 401
    
    @jwt_required(optional=False)    
    @app.route('/api/v1/get_transactions', methods=['GET'])
    def get_transactions():
        verify_jwt_in_request()
        current_identity = get_jwt_identity()
        if (current_identity):
            received = db.query('transactions', Query().receiver == current_identity['user']['user_id'])
            sent = db.query('transactions', Query().sender == current_identity['user']['user_id'])
            transactions = received + sent
            return jsonify({
                'status': 'success',
                'message': 'تراکنش های شما با موفقیت دریافت شد',
                'transactions': transactions
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'خطایی در اهراز هویت رخ داده است'
            }), 401

    @jwt_required(optional=False)
    @app.route('/api/v1/get_current_price', methods=['GET'])
    def get_current_price():
        verify_jwt_in_request()
        current_identity = get_jwt_identity()
        if (current_identity):
            if (is_first_payment_performed()):
                latest_transaction = get_latest_transaction(db)
                hooger_price = float(latest_transaction["transaction"]['hooger_price'])
                amount = float(latest_transaction["transaction"]['amount'])
                final_value = hooger_price * amount
                if (final_value > hooger_price):
                    price = (final_value + hooger_price) / amount
                    return jsonify({
                        'status': 'success',
                        'message': 'دریافت قیمت با موفقیت انجام شد',
                        'price': price
                    }), 200
                elif (final_value < hooger_price):
                    price = hooger_price - (final_value * amount)
                    return jsonify({
                        'status': 'success',
                        'message': 'دریافت قیمت با موفقیت انجام شد',
                        'price': price
                    }), 200
                else:
                    return jsonify({
                        'status': 'success',
                        'message': 'دریافت قیمت با موفقیت انجام شد',
                        'price': hooger_price
                    }), 200
            else:
                return jsonify({
                    'status': 'success',
                    'message': 'دریافت قیمت با موفقیت انجام شد',
                    'price': initial_hgr_price
                }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'خطایی در اهراز هویت رخ داده است'
            }), 401
    
    @jwt_required(optional=False)
    @app.route('/api/v1/get_today_prices', methods=['GET'])
    def get_today_prices():
        verify_jwt_in_request()
        current_identity = get_jwt_identity()
        if (current_identity):
            current_year = str(datetime.datetime.now().year)
            current_month = datetime.datetime.now().month
            current_month = f'0{str(current_month)}' if len(str(current_month)) == 1 else str(current_month)
            current_day = datetime.datetime.now().day
            current_day = f'0{str(current_day)}' if len(str(current_day)) == 1 else str(current_day)
            _date = current_year + '-' + current_month + '-' + current_day
            queryResult = db.query('price_history', Query().ts_time.matches(_date))
            return jsonify({
                'status': 'success',
                'message': 'دریافت قیمت با موفقیت انجام شد',
                'prices': queryResult
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'خطایی در اهراز هویت رخ داده است'
            }), 401
    
    @jwt_required(optional=False)
    @app.route('/api/v1/get_supply', methods=['GET'])
    def get_supply():
        verify_jwt_in_request()
        current_identity = get_jwt_identity()
        if (current_identity):
            userId = current_identity['user']['user_id']
            user_supply = get_user_supply(db, userId)
            return jsonify({
                'status': 'success',
                'message': 'دریافت موجودی با موفقیت انجام شد',
                'supply': user_supply
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'خطایی در اهراز هویت رخ داده است'
            }), 401
    
    @jwt_required(optional=False)
    @app.route('/api/v1/sell_coin', methods=['POST'])
    def sell_coin():
        verify_jwt_in_request()
        current_identity = get_jwt_identity()
        if (current_identity):
            global server_public_address
            sender_public_address = request.json["sender"]
            receiver_public_address = get_account_public_address(get_server_account(db)['username'])
            hooger_price = request.json['hooger_price']
            amount = request.json['amount']
            transaction = {
                'ts_id': str(uuid4()).upper(),
                'sender': sender_public_address,
                'receiver': receiver_public_address,
                'hooger_price': hooger_price,
                'amount': amount,
                'ts_time': str(datetime.datetime.now()),
                'ts_timestamp': int(time.time()),
                'ts_type': 'sell_coin'
            }
            db.insert('transactions', transaction)
            db.insertOrUpdate('transactions_history', {'id': 'latest_transtion', 'transaction': transaction})
            set_key(key_to_set='FIRST_PAYMENT_PERFORMED', value_to_set='true', dotenv_path='.env')
            track_hooger_price_change(db, transaction['ts_type'])
            return jsonify({
                'status': 'success',
                'message': 'فروش با موفقیت انجام شد'
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'خطایی در اهراز هویت رخ داده است'
            }), 401
    
    @app.route('/api/v1/save_public_key', methods=['POST'])
    def save_public_key():
        publicKey = request.headers.get("Publickey")
        username = request.json['username']
        public_key = format_public_key(request.json['public_key'])
        
        if (os.path.exists(f'keys/{username}/') == False):
            os.makedirs(f'keys/{username}/')
            file = open(f'keys/{username}/public-key.pub', 'w+')
            file.write(public_key)
            file.close()
            return jsonify({
                'status': 'success',
                'message': 'کلید عمومی با موفقیت ذخیره شد'
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'کلید عمومی موجود است'
            })
        
    @app.route('/api/v1/create_account', methods=['POST'])
    def create_account():
        account_id = str(uuid4()).upper()
        username = request.json['username']
        publicKey = request.headers.get("Publickey")
        password = Security.generate_hooger_passphrase()
        queryResult = db.query('users', Query().username == username)
        if (len(queryResult) == 0):
            hashed_password = Security.sha512(password)
            data = {
                'account_id': account_id,
                'username': username,
                'password': hashed_password
            }
            db.insert('users', data)
            return jsonify({
                'status': 'success',
                'message': 'حساب کاربری با موفقیت ایجاد شد',
                'data': {
                    'username': username,
                    'password': password
                }
            }), 201
        else:
            return jsonify({
                'status': 'error',
                'message': 'حسابی با این نام کاربری وجود دارد.'
            })

    @app.route('/api/v1/get_server_info', methods=['GET'])
    def get_server_info():
        global server_account
        server_name = getEnv('SERVER_NAME')
        server_version = getEnv('SERVER_VERSION')
        server_description = getEnv('SERVER_DESCRIPTION')
        public_key = getPublicKey(server_account)
        return jsonify({
            'status': 'success',
            'message': 'دریافت اطلاعات سرور با موفقیت انجام شد',
            'data': {
                'server_name': server_name,
                'server_version': server_version,
                'server_description': server_description,
                'public_key': public_key
            }
        }), 200
    
    port = 5432
    if (is_port_in_use(port)):
        port = random.randint(5000, 6000)
    print(f'{Fore.GREEN}Server running on port {port}{Style.RESET_ALL}')
    app.run(host='192.168.43.17', port=port, debug=True)

def format_public_key(pub_key):
    n = 64
    public_key_arr = [pub_key[i:i+n] for i in range(0, len(pub_key), n)]
    public_key = "-----BEGIN PUBLIC KEY-----\n"
    for i in public_key_arr:
        public_key += i + "\n"
    public_key += "-----END PUBLIC KEY-----"
    return public_key

def crypto_middleware(userEncrypted: bool):
    def _crypto_middleware(func):
        @wraps(func)
        def __crypto_middleware(*args, **kwargs):
            global request, parsedRequests
            if (userEncrypted):
                verify_jwt_in_request()
                current_identity = get_jwt_identity()
                username = current_identity['user']['username']
                privateKey = getPrivateKey(username)
                parsedRequests = request.form.to_dict(flat=False)
                parsedRequests['data'] = ast.literal_eval(Keytil.rsa_decrypt(parsedRequests['data'][0], privateKey).decode('utf-8'))
            else:
                privateKey = getPrivateKey(server_account)
                parsedRequests = request.form.to_dict(flat=False)
                symmetricKey = Keytil.rsa_decrypt(parsedRequests["key"][0], privateKey).decode('utf-8')
                print(parsedRequests["data"][0] + "\n" + symmetricKey)
                dec = Keytil.aes_decrypt(parsedRequests["data"][0], symmetricKey).decode('utf-8')
                print(f"# {dec}")
                parsedRequests["data"] = ast.literal_eval(dec)
                print(parsedRequests)
            result = func(*args, **kwargs)
            return result
        return __crypto_middleware
    return _crypto_middleware

def encrypt_response(response: str, crypt_key, status_code = None):
    if (status_code != None):
        return (Keytil.encrypt_response(response, crypt_key)
                if is_encrypted_ecosystem() else jsonify(response)), status_code
    else:
        return (Keytil.encrypt_response(response, crypt_key)
                if is_encrypted_ecosystem() else jsonify(response))

def getPublicKey(username):
    file = open(f'keys/{username}/public-key.pub', 'r')
    publicKey = file.read().replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace('\n', '')
    file.close()
    return publicKey

def getPrivateKey(username):
    file = open(f'keys/{username}/private-key.pem', 'r')
    publicKey = file.read().replace('-----BEGIN RSA PRIVATE KEY-----', '').replace('-----END RSA PRIVATE KEY-----', '').replace('\n', '')
    file.close()
    return publicKey

def is_encrypted_ecosystem() -> bool:
    return strtobool(getEnv('ENCRYPTED_ECOSYSTEM'))

def getEnv(key):
    return get_key(key_to_get=key, dotenv_path=".env")

def track_hooger_price_change(db: Database, ts_type: str):
    latest_transaction = get_latest_transaction(db)
    latest_hooger_price = float(latest_transaction["transaction"]['hooger_price'])
    latest_amount = float(latest_transaction["transaction"]['amount'])
    final_value = latest_hooger_price * latest_amount
    if (final_value > latest_hooger_price or final_value < latest_hooger_price):
        db.insert('price_history', {'id': str(uuid4()).upper(), 'price': latest_hooger_price
        , 'ts_time': str(datetime.datetime.now())
        , 'ts_timestamp': int(time.time())
        , 'ts_type': ts_type})

def get_user_supply(db: Database, userId: str):
    received = db.query('transactions', Query().receiver == userId)
    sent = db.query('transactions', Query().sender == userId)
    transactions = received + sent
    finalSupply = 0
    for i in transactions:
        if (i['sender'] == userId):
            finalSupply -= float(i['amount'])
        else:
            finalSupply += float(i['amount'])
    return finalSupply

def get_latest_transaction(db: Database):
    queryResult = db.query('transactions_history', Query().id == 'latest_transtion')
    if (len(queryResult) > 0):
        return queryResult[0]
    else:
        return None

def get_server_account(db: Database):
    query = db.query('users', Query().username == server_account)
    return query[0]

def initilize_server(db: Database):
    global server_account, server_passphrase, server_public_address
    if (is_server_wallet_exists(db) == False):
        account_id = str(uuid4()).upper()
        data = {
            'account_id': str(uuid4()).upper(),
            'username': server_account,
            'password': server_passphrase
        }
        db.insert('users', data)
        time.sleep(2)
        if (is_server_keypairs_exist()):
            os.remove(f'keys/{server_account}/public-key.pub')
            os.remove(f'keys/{server_account}/private-key.pem')
        else:            
            keytil = Keytil()
            keytil.generate_key_pairs(server_account, server_passphrase.encode('utf-8'))
            server_public_address = get_account_public_address(get_server_account(db)['username'])
        server_public_address = get_account_public_address(server_account)

def initilize_price(db: Database):
    global initial_hgr_price
    db.insertOrUpdate('price_history', {'id': 'initial_price', 'price': initial_hgr_price
    , 'ts_time': '2022-04-25 00:00:00.000000'
    , 'ts_timestamp': 1650844800
    , 'ts_type': 'chain_initialization'})


def is_server_wallet_exists(db: Database) -> bool:
    global server_account
    queryResult = db.query('users', Query().username == server_account)
    return len(queryResult) > 0

def is_server_keypairs_exist() -> bool:
    global server_account
    return os.path.exists(f'keys/{server_account}/public-key.pub') and os.path.exists(f'keys/{server_account}/private-key.pem')

def is_first_payment_performed() -> bool:
    load_dotenv()
    return strtobool(getEnv("FIRST_PAYMENT_PERFORMED"))

def generate_account_id(id: str):
    hash_object = hashlib.sha1(id.encode('utf-8'))
    return "0x" + hash_object.hexdigest()

def get_account_public_address(username: str):
    public_key = get_public_key(username)
    sha512_result = hashlib.sha512(public_key.encode('utf-8')).hexdigest()
    sha384_result = hashlib.sha384(sha512_result.encode('utf-8')).hexdigest()
    sha256_result = hashlib.sha256(sha384_result.encode('utf-8')).hexdigest()
    sha128_result = hashlib.sha1(sha256_result.encode('utf-8')).hexdigest()
    base58_result = base58.b58encode(sha128_result.encode('utf-8')).decode('utf-8')
    public_address = base58_result
    return public_address

def get_public_key(username: str):
    file = open(f'keys/{username}/public-key.pub', 'r')
    public_key = file.read()
    return public_key

if __name__ == "__main__":
    main()
    # key = "/Veu4N8B0fVAZxRo3mXuJg=="
    # data = {
    #     'username': 'armin'
    # }
    # enc = Keytil.aes_encrypt(str(data), key).decode('utf-8')
    # dec = Keytil.aes_decrypt(enc, key).decode('utf-8')
    # print(enc, dec)