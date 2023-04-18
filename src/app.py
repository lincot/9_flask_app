from flask import Flask, request
from hashlib import pbkdf2_hmac
from base64 import b64encode, b64decode
import json
import secrets
import datetime

application = Flask(__name__)


@application.route('/users/register', methods=['POST'])
def register():
    with open('users.json') as f:
        users = json.load(f)
    data = json.loads(request.get_data())
    if data['username'] in (x['username'] for x in users):
        return 'already registered'
    salt = secrets.token_bytes(512 // 8)
    hash = pbkdf2_hmac('sha256', data['password'].encode(), salt, 100_000)
    users.append(
        {'username': data['username'],
            'hash': b64encode(hash).decode(),
            'salt': b64encode(salt).decode(),
            'registration_date': str(datetime.datetime.utcnow())
         })
    with open('users.json', 'w') as f:
        json.dump(users, f)
    return 'ok'


@application.route('/users/login', methods=['POST'])
def login():
    with open('users.json') as f:
        users = json.load(f)
    data = json.loads(request.get_data())
    try:
        user = next(filter(lambda x: x['username'] == data['username'], users))
    except StopIteration:
        return 'no such user'
    if pbkdf2_hmac('sha256', data['password'].encode(),
                   b64decode(user["salt"]), 100_000) \
            == b64decode(user["hash"]):
        return 'ok'
    return 'wrong password'


@application.route('/users/<string:username>', methods=['GET'])
def get_user(username):
    with open('users.json') as f:
        users = json.load(f)
    try:
        return next(filter(lambda x: x['username'] == username, users))
    except StopIteration:
        return 'no such user'


@application.route('/')
def root():
    return 'hello'


def main():
    application.run(debug=True, ssl_context='adhoc')


if __name__ == '__main__':
    main()
