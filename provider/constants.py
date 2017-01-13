import os
import web
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

db_path = os.path.join(BASE_PATH, *DBPATH)
db_path = os.path.join(db_path, DBFILENAME)
db = web.database(dbn='sqlite', db=db_path)
db.query("PRAGMA foreign_keys = ON;")

render = web.template.render(os.path.join(BASE_PATH, 'templates'))

#if web.config.get('_session') is None:
#    session = web.session.Session(app, web.session.DiskStore('sessions'), {'count': 0})
#    web.config._session = session
#else:
#    session = web.config._session

