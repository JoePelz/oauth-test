import os
import web
import sys

BASE_PATH = os.path.dirname(__file__)
DBPATH = ['data']
DBFILENAME = 'dev.db'

sys.path.append(BASE_PATH)

urls = (
    '/', 'Dummy',  # Omit the overview page and go straight to map (no content in overview anyway)
    '/authorize', 'Authorize',
    '/token', 'Token',
)

db_path = os.path.join(BASE_PATH, *DBPATH)
db_path = os.path.join(db_path, DBFILENAME)
db = web.database(dbn='sqlite', db=db_path)

render = web.template.render('./')

#if web.config.get('_session') is None:
#    session = web.session.Session(app, web.session.DiskStore('sessions'), {'count': 0})
#    web.config._session = session
#else:
#    session = web.config._session

