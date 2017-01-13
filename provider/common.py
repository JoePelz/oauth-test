import os
import dbsetup
import constants
import web
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


db = dbsetup.get_db()

render = web.template.render(os.path.join(constants.BASE_PATH, 'templates'))

session_store = web.session.DBStore(db, 'sessions')
