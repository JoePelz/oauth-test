import os
import base64
import math


def b64_url_encode(byte_string):
    return base64.b64encode(byte_string, "-_")


def generate_salt(length):
    """
    Generate a cryptographically secure random base64 code of the desired length
    :param length: The desired output string length
    :return: A base64 encoded salt
    """
    # base64 stores 6 bits per symbol but os.urandom gives 8 bits per symbol
    bytes_needed = int(math.ceil(length * 6.0 / 8.0))
    random_bytes = os.urandom(bytes_needed)
    encoded = b64_url_encode(random_bytes)
    return encoded[:length]


class Applications(object):
    MAX_ATTEMPTS = 25

    def __init__(self, db):
        self.db = db
        self.table = "Applications"

    def generate_unique_id(self):
        matches = True
        attempts = 0
        app_id = '12345678'
        while matches and attempts < Applications.MAX_ATTEMPTS:
            app_id = generate_salt(8)
            qvars = {'aid': app_id}
            rows = self.db.select(self.table, where="app_id=$aid", vars=qvars)
            matches = rows.first()
            attempts += 1
        if matches:
            raise ValueError("Failed to generate a unique id.")

        return app_id

    def exists(self, application_id):
        qvars = {
            "aid": application_id
        }
        rows = self.db.select(self.table, what="1", where="app_id=$aid", vars=qvars, limit=1)
        app = rows.first()
        return app is not None

    def get(self, application_id):
        """
        :param application_id: unique id to search for
        :return: All user details of a client, if a match is found. Else, None.
        """
        qvars = {
            "aid": application_id
        }
        rows = self.db.select(self.table, where="app_id=$aid", vars=qvars, limit=1)
        app = rows.first()
        return app

    def add(self, name, owner_id, scopes, redirect_uris, default_scopes=None, default_redirect_uri=None):
        """
        :param name: string; nice name for app
        :param owner_id: id of application registrant (owner)
        :param scopes: list; List of scopes that can be granted
        :param redirect_uris: list; List of uris that can be redirected to after login.
        :param default_scopes: list; optional; Default scopes to grant if none requested.
        :param default_redirect_uri: list; optional; link to redirect to after login if none supplied.
        :return: the id of the newly created app
        """
        qvars = {
            'nicename': name,
            'owner_id': owner_id,
            'scopes': " ".join(scopes),
            'redirect_uris': " ".join(redirect_uris)
        }
        if default_scopes:
            qvars['default_scopes'] = default_scopes
        if default_redirect_uri:
            qvars['default_redirect_uri'] = default_redirect_uri

        # a unique ID for the app
        app_id = self.generate_unique_id()
        qvars['app_id'] = app_id

        # generate a secret key to use
        secret = generate_salt(32)
        qvars['secret_key'] = secret

        qvars['grant_type'] = 'authorization_code'  # only authorization_code is supported
        qvars['response_type'] = 'code'  # only authorization_code is supported

        self.db.insert(self.table, **qvars)
        return app_id
