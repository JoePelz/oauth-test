import time
import os
import bcrypt
import hashlib
import binascii
import hmac
import base64
import math


def b64_url_encode(bytes):
    return base64.b64encode(bytes, "-_")


def generate_salt(length):
    """
    Generate a cryptographically secure random base64 code of the desired length
    :param length: The desired output string length
    :return: A base64 encoded salt
    """
    # base64 stores 6 bits per symbol but os.urandom gives 8 bits per symbol
    bytes_needed = int(math.ceil(length * 6.0 / 8.0))
    bytes = os.urandom(bytes_needed)
    encoded = b64_url_encode(bytes)
    return encoded[:length]


class Users(object):
    def __init__(self, db):
        self.db = db
        self.table = "Users"

    def update_access_time(self, email):
        """
        Updates the "last_access" time to the current server time, for the user with the given email address
        :param email:  The email to identify a user
        :return: None
        """
        qvars = {
            "email": email
        }
        now = int(time.time())
        self.db.update(self.table, "email=$email", vars=qvars, last_access=now)

    def get_login_cookie(self, user_id):
        token = generate_salt(32)
        secret_key = generate_salt(32)
        self.storeRememberToken(user_id, token, secret_key)
        cookie_text = "{0}:{1}".format(user_id, token)
        dk = hashlib.pbkdf2_hmac('sha256', cookie_text, secret_key, 100000)
        ascii_hash = binascii.hexlify(dk)
        cookie_text = "{0}:{1}".format(cookie_text, ascii_hash)
        return cookie_text

    def validate_login_cookie(self, user_id, token, cookie_hash):
        """
        Validate a "remember me" cookie meant to keep a user logged in.
        :param cookie: The cookie saved to remember a user being logged in.
        :return: True or False if the cookie matches a login credential
        """
        valid = False
        user = self.get_by_id(user_id)
        if user:
            print("memory of user found")
            saved_token = user.remember_token
            saved_key = user.secret_key
            dk = hashlib.pbkdf2_hmac('sha256', "{0}:{1}".format(user_id, saved_token), saved_key, 100000)
            ascii_hash = binascii.hexlify(dk)
            matches = hmac.compare_digest("{0}:{1}:{2}".format(user_id, token, cookie_hash), "{0}:{1}:{2}".format(user_id, saved_token, ascii_hash))
            if matches:
                print("user codes match! User is remembered")
                valid = True
        return valid

    def get_by_id(self, account):
        qvars = {
            "aid": account
        }
        rows = self.db.select(self.table, where='id=$aid', vars=qvars, limit=1)
        user = rows.first()
        return user

    def get(self, email, password):
        """
        :param email: The user email to search for
        :param password: The use password that corresponds to the email above
        :return: All user details if a match is found, else None.
        """
        qvars = {
            "email": email
        }
        rows = self.db.select(self.table, where="email=$email", vars=qvars, limit=1)
        user = rows.first()
        if user:
            hashed_password = user.password.encode(encoding='utf-8')
            ascii_password = password.encode(encoding='utf-8')
            password_matches = bcrypt.hashpw(ascii_password, hashed_password) == hashed_password
            if password_matches:
                self.update_access_time(email)
                return user
            else:
                return None
        else:
            return None

    def add(self, email, password, **kwargs):
        qvars = {
            "email": email,
        }
        rows = self.db.select(self.table, where="email=$email", vars=qvars, limit=1)
        user = rows.first()
        if user:
            raise KeyError("Email already exists")

        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        user_id = self.db.insert(self.table, email=email, password=hashed_password, **kwargs)

        return user_id

    def storeRememberToken(self, account_id, token, secret):
        qvars = {
            'aid': account_id
        }
        self.db.update(self.table, "id=$aid", vars=qvars, remember_token=token, secret_key=secret)