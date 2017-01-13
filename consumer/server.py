import os
import urllib
import urllib2
import base64
import web
web.config.debug = False

# ====================================================


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


def getRequest(url, headers=None, args=None):
    """
    :param url:  The url to send the request to.  e.g.  https://example.org/test
    :param headers:  dictionary of headers. e.g. {"Accepts": "text/html"}
    :param args: dictionary of GET parameters to urlencode and append to the url
    :return: the server response
    """
    print("Making GET request to {0}".format(url))
    if args:
        augmented_url = "{0}?{1}".format(url, urllib.urlencode(args))
    else:
        augmented_url = url

    if not headers:
        headers = {}

    headers['Accept'] = "application/json"
    if 'access_token' in session:
        headers['Authorization'] = 'Bearer {0}'.format(session['access_token'])

    request = urllib2.Request(augmented_url, headers=headers)
    response = urllib2.urlopen(request).read()

    return response

def postRequest(url, headers=None, args=None):
    """
    :param url:  The url to send the request to.  e.g.  https://example.org/test
    :param headers:  dictionary of headers. e.g. {"Accepts": "text/html"}
    :param args: dictionary of POST parameters to urlencode and append to the url
    :return: the server response
    """
    print("Making POST request to {0}".format(url))
    if args:
        post_data = urllib.urlencode(args)
    else:
        post_data = ''

    if not headers:
        headers = {}

    headers['Accept'] = "application/json"
    if 'access_token' in session:
        headers['Authorization'] = 'Bearer {0}'.format(session['access_token'])

    request = urllib2.Request(url, headers=headers)
    response = urllib2.urlopen(request, post_data).read()

    return response

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

    def retrieve_key(self, GET_data):
        # Verify the state matches our stored state
        if 'state' not in GET_data or GET_data['state'] != session['state']:
            print("State salt does not match.")
            raise web.seeother("/public")

        # Exchange the auth code for a token
        params = {
            'client_id': "0123456789abcdef",
            'redirect_uri': 'http://localhost:8080/private',
            'state': session['state'],
            'code': GET_data['code']
        }
        token = postRequest(tokenURL, args=params)
        print("token received:\n{0}".format(token))
        session['bearer_token'] = token

        raise web.seeother("/private")

    def GET(self):
        data = web.input()
        report_init("PRIVATE", "GET", session, data)

        if 'code' in data:
            self.retrieve_key(data)

        if 'bearer_token' in session:
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

    def GET(self):
        data = web.input()
        report_init("LOGIN", "GET", session, data)

        # Generate a random hash and store in the session for security
        seq = os.urandom(48)
        enc_seq = base64.b64encode(seq)
        session['state'] = enc_seq
        session.pop('access_token', None)

        params = {
            'client_id': "0123456789abcdef",
            'redirect_uri': 'http://localhost:8080/private',
            'response_type': 'code',
            'scope': 'base admin',
            'state': session['state']
        }

        # Redirect the user to the authorization page
        qstring = urllib.urlencode(params)
        print("redirecting to {0}?{1}".format(authorizeURL, qstring))
        raise web.seeother("{0}?{1}".format(authorizeURL, qstring))

    def POST(self):
        data = web.input()
        report_init("LOGIN", "POST", session, data)
        GET_data = web.input()


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
# This is the URL we'll send the user to first to get their authorization
authorizeURL = 'http://localhost:8081/authorize'

# This is the endpoint our server will request an access token from
tokenURL = 'http://localhost:8081/token'

app = web.application(urls, globals())

web.config.session_parameters['cookie_path'] = "/"

# set up database
db_path = os.path.join(BASE_PATH, "data", "dev.db")
db = web.database(dbn='sqlite', db=db_path)
db.query("PRAGMA foreign_keys = ON;")
exec_sql(db, os.path.join(BASE_PATH, "sql", "session_table.sql"))

# set up session
store = web.session.DBStore(db, 'sessions')
session = web.session.Session(app, store)
session['dummy'] = '123'

render = web.template.render('./')


if __name__ == "__main__":
    app.run()
