import os
import web
import pprint
web.config.debug = False
from web.wsgiserver import CherryPyWSGIServer
from ConfigParser import SafeConfigParser
import oauth_consumer
import oauthlib.oauth2.rfc6749.errors


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
        self.oauth = oauth_consumer.Authorization(
            session=session,
            authorization_url=config.get('authentication', 'authorization_url'),
            token_url=config.get('authentication', 'token_url'),
            client_id=config.get('credentials', 'client_id'),
            client_secret=config.get('credentials', 'client_secret'),
            default_redirect_uri=config.get('general', 'redirect_uri'),
            default_scope_requested=config.get('general', 'scope'))

    def GET(self):
        data = web.input()
        report_init("PRIVATE", "GET", session, data)

        # if the user is already logged in, just show them the page
        if session.get('logged_in', False) is True:
            return render.private_page()

        # send back to public page
        print("redirecting to /public")
        raise web.seeother("/public")

    def POST(self):
        data = web.input()
        report_init("PRIVATE", "POST", session, data)


class Login(object):
    def __init__(self):
        self.redirect_uri = unicode(config.get('general', 'login_uri'))
        self.scope = unicode(config.get('general', 'scope'))
        self.oauth = oauth_consumer.Authorization(
            session=session,
            authorization_url=config.get('authentication', 'authorization_url'),
            token_url=config.get('authentication', 'token_url'),
            client_id=config.get('credentials', 'client_id'),
            client_secret=config.get('credentials', 'client_secret'),
            default_redirect_uri=config.get('general', 'redirect_uri'),
            default_scope_requested=config.get('general', 'scope'))

    def get_token(self):
        authorization_response = "{scheme}://{host}{port}{path}".format(
            scheme=web.ctx.env.get('wsgi.url_scheme', 'https'),
            host=web.ctx.env['SERVER_NAME'],
            port=':{0}'.format(web.ctx.env['SERVER_PORT']),
            path=web.ctx.env['REQUEST_URI'])
        try:
            # redirect_uri must match between get_auth_code and get_token.
            # scope must match between get_auth_code and get_token
            token = self.oauth.fetch_token(authorization_response, redirect_uri=self.redirect_uri, scope=self.scope)
        except oauthlib.oauth2.rfc6749.errors.AccessDeniedError:
            print("Access was denied. Reason unknown.")
            return False
        except oauthlib.oauth2.rfc6749.errors.InvalidGrantError:
            print("Access was denied. Error: Invalid Grant.")
            return False

        print("\n\nToken acquired!")
        pprint.pprint(token)
        print("")
        return True

    def get_auth_code(self):
        print("redirect_uri is {0}".format(self.redirect_uri))
        # redirect_uri must match between get_auth_code and get_token.
        # scope must match between get_auth_code and get_token
        authorization_url = self.oauth.get_auth_url(redirect_uri=self.redirect_uri, scope=self.scope)
        print("redirecting to {0}".format(authorization_url))
        raise web.seeother(authorization_url)

    def GET(self):
        data = web.input()
        report_init("LOGIN", "GET", session, data)

        if 'state' in data and 'code' in data:
            print("state and code found. Assuming to be at fetch_token step.")
            if self.get_token():
                print("get_token returned True. setting logged_in to True")
                session['logged_in'] = True
                raise web.seeother('/private')
            else:
                print("get_token returned False. setting logged_in to False")
                session['logged_in'] = False
                raise web.seeother('/public')
        else:
            print("begin authentication process.")
            self.get_auth_code()

        # this code should be unreachable.
        raise web.seeother('/public')

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

CherryPyWSGIServer.ssl_certificate = "./" + config.get('ssl', 'certificate')
CherryPyWSGIServer.ssl_private_key = "./" + config.get('ssl', 'key')

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
