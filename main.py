import hashlib
import os
import uuid
from urllib.parse import urlencode

import jwt  # PyJWT
import requests
from dotenv import load_dotenv


def send_without_parameter(path):
    payload = {
        'access_key': ACCESS_KEY,
        'nonce': str(uuid.uuid4()),
    }

    jwt_token = jwt.encode(payload, SECRET_KEY)
    authorization_token = 'Bearer {}'.format(jwt_token)
    headers = {"Authorization": authorization_token}
    res = requests.get(SERVER_URL + path, headers=headers)
    return res.json()


# key[]=value1&key[]=value2 ...
def send_with_parameter(path, query):
    # query는 dict 타입입니다.
    m = hashlib.sha512()
    m.update(urlencode(query).encode())
    query_hash = m.hexdigest()

    payload = {
        'access_key': ACCESS_KEY,
        'nonce': str(uuid.uuid4()),
        'query_hash': query_hash,
        'query_hash_alg': 'SHA512',
    }

    jwt_token = jwt.encode(payload, SECRET_KEY)
    authorization_token = 'Bearer {}'.format(jwt_token)
    headers = {"Authorization": authorization_token}
    res = requests.get(SERVER_URL + path, headers=headers)
    return res


def load_envs():
    global ACCESS_KEY
    global SECRET_KEY
    global SERVER_URL
    load_dotenv()
    ACCESS_KEY = os.environ.get('ACCESS')
    SECRET_KEY = os.environ.get('SECRET')
    SERVER_URL = os.environ.get('URL')


def main():
    load_envs()
    my_prop = send_without_parameter("/v1/accounts")
    print(my_prop)


if __name__ == '__main__':
    main()
