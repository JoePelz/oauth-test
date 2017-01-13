import os
import sys

BASE_PATH = os.path.dirname(__file__)
DBPATH = ['data']
DBFILENAME = 'dev.db'

sys.path.append(BASE_PATH)

urls = (
    '/', 'Home',
    '/login', 'Login',
    '/logout', 'Logout',
    '/authorize', 'Authorize',
    '/token', 'Token',
)
