import os
import sys
import urllib
import urllib2
import base64
import logging
import requests_oauthlib
import web
web.config.debug = False
from web.wsgiserver import CherryPyWSGIServer
from ConfigParser import SafeConfigParser


log = logging.getLogger('oauthlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)
log = logging.getLogger('requests_oauthlib.oauth2_session')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)

# ====================================================


def create_db(base_path, path, filename):

    # make sure folder exists
    db_path = os.path.join(base_path, *path)
    if not os.path.exists(db_path):
        os.makedirs(db_path)

    # make sure db exists
    full_path = os.path.join(db_path, filename)
    if not os.path.exists(full_path):
        f = open(full_path, 'a')
        f.close()


def parse_sql_file(path):
    with open(path, 'r') as f:
        lines = f.readlines()
    # remove comment lines
    lines = [i for i in lines if not i.startswith("--")]
    # join into one long string
    script = " ".join(lines)
    # split string into a list of commands
    commands = script.split(";")
    # ignore empty statements (like trailing newlines)
    commands = filter(lambda x: bool(x.strip()), commands)
    return commands


def exec_sql(connection, path):
    commands = parse_sql_file(path)
    for command in commands:
        connection.query(command)


def report_init(page, protocol, session, webinput):
    print(" {page} {protocol} ".format(page=page, protocol=protocol).center(50, '-'))
    print("SESSION ID: {0}".format(web.ctx.environ.get('HTTP_COOKIE', 'unknown')))
    print("SESSION KEYS: {0}".format(session.keys()))
    print("SESSION: {0}".format(dict(session)))
    print("WEB INPUT: {0}".format(webinput))
    print("-"*50)
    print("\n")


class Public(object):
    def __init__(self):
        if "counter" not in session:
            session['counter'] = 0
        else:
            session['counter'] += 1

    def GET(self):
        data = web.input()
        report_init("PUBLIC", "GET", session, data)

        return render.public_page()

    def POST(self):
        data = web.input()
        report_init("PUBLIC", "POST", session, data)

        return render.public_page()


class Private(object):
    def __init__(self):
        if "counter" not in session:
            session['counter'] = 0
        else:
            session['counter'] += 1
        self.redirect_uri = unicode(config.get('general', 'redirect_uri'))
        self.response_type = u'code'
        self.client_id = unicode(config.get('credentials', 'client_id'))
        self.client_secret = unicode(config.get('credentials', 'client_secret'))
        self.scope = unicode(config.get('general', 'scope'))

    def retrieve_key(self, GET_data):
        print("retrieving key.")
        authorization_response = "{scheme}://{host}{port}{path}".format(
            scheme=web.ctx.env.get('wsgi.url_scheme', 'https'),
            host=web.ctx.env['SERVER_NAME'],
            port=':{0}'.format(web.ctx.env['SERVER_PORT']),
            path=web.ctx.env['REQUEST_URI']
        )
        oauth = requests_oauthlib.OAuth2Session(self.client_id, redirect_uri=self.redirect_uri, scope=self.scope)
        print("authorization response is {0}".format(authorization_response))

        # TODO: verify = FALSE only for testing
        token = oauth.fetch_token(
            config.get('authentication', 'token_url'),
            authorization_response=authorization_response,
            client_secret=self.client_secret,
            verify=False)
        print("token is {0}".format(token))
        session['bearer_token'] = token

    def GET(self):
        data = web.input()
        report_init("PRIVATE", "GET", session, data)

        if 'code' in data:
            print('"code" encountered. Retrieving key.')
            self.retrieve_key(data)

        if 'bearer_token' in session:
            print('"bearer_token" is installed. granting access.')
            return render.private_page()
        else:
            print("redirecting to /public")
            raise web.seeother("/public")

    def POST(self):
        data = web.input()
        report_init("PRIVATE", "POST", session, data)
        print("redirecting back to public.")
        raise web.seeother("/public")


class Login(object):
    def __init__(self):
        if "counter" not in session:
            session['counter'] = 0
        else:
            session['counter'] += 1
        self.redirect_uri = unicode(config.get('general', 'redirect_uri'))
        self.response_type = u'code'
        self.client_id = unicode(config.get('credentials', 'client_id'))
        self.client_secret = unicode(config.get('credentials', 'client_secret'))
        self.scope = unicode(config.get('general', 'scope'))


    def GET(self):
        data = web.input()
        report_init("LOGIN", "GET", session, data)

        # Generate a random hash and store in the session for security
        seq = os.urandom(48)
        enc_seq = base64.b64encode(seq)
        session['state'] = enc_seq
        session.pop('access_token', None)
        print("redirect_uri is {0}".format(self.redirect_uri))
        print("scope is {0}, {0.__class__}".format(self.scope))
        oauth = requests_oauthlib.OAuth2Session(self.client_id, redirect_uri=self.redirect_uri, scope=unicode(self.scope))
        authorization_url, state = oauth.authorization_url(
            config.get('authentication', 'authorization_url'),
            # access_type and approval_prompt are Google specific extra
            # parameters.
            access_type="offline", approval_prompt="force")
        print("---\nAuthorizing.")
        print("Auth_url is {0}".format(authorization_url[:50]))
        print("State is {0}".format(str(state)[:50]))
        print("redirecting to {0}".format(authorization_url))
        raise web.seeother(authorization_url)

    def POST(self):
        data = web.input()
        report_init("LOGIN", "POST", session, data)


class Logout(object):
    def GET(self):
        data = web.input()
        report_init("LOGOUT", "GET", session, data)
        session.kill()
        raise web.seeother("/public")

    def POST(self):
        data = web.input()
        report_init("LOGOUT", "POST", session, data)
        session.kill()
        raise web.seeother("/public")


# Manage routing from here. Regex matches URL and chooses class by name
urls = (
    '/', 'Public',  # Omit the overview page and go straight to map (no content in overview anyway)
    '/public', 'Public',
    '/private', 'Private',
    '/login', 'Login',
    '/logout', 'Logout',
)

BASE_PATH = "."
DBPATH = ['data']
DBFILENAME = 'dev.db'

config = SafeConfigParser()
config.read("app.cfg")

# openssl req -x509 -sha256 -nodes -newkey rsa:2048 -days 365 -keyout localhost.key -out localhost.crt
CherryPyWSGIServer.ssl_certificate = "./localhost.crt"
CherryPyWSGIServer.ssl_private_key = "./localhost.key"

app = web.application(urls, globals())

web.config.session_parameters['cookie_path'] = "/"

# set up database
create_db(BASE_PATH, DBPATH, DBFILENAME)
db_path = os.path.join(BASE_PATH, *DBPATH)
db_path = os.path.join(db_path, DBFILENAME)
db = web.database(dbn='sqlite', db=db_path)
exec_sql(db, os.path.join(BASE_PATH, "sql", "session_table.sql"))
db.query("PRAGMA foreign_keys = ON;")

# set up session
store = web.session.DBStore(db, 'sessions')
session = web.session.Session(app, store)

render = web.template.render('./')


if __name__ == "__main__":
    app.run()
