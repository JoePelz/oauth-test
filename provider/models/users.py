import time
import bcrypt

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