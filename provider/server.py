import traceback
import web
web.config.debug = False
import constants
from request_validator import MyRequestValidator
from oauthlib.oauth2 import WebApplicationServer
import oauthlib.oauth2.rfc6749.errors as errors
import common
import logging
import sys
import hashlib
import binascii
import hmac
from models.users import Users
import time

# enable logging, while under development
log = logging.getLogger('oauthlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)

app = web.application(constants.urls, globals())
session = web.session.Session(app, common.session_store)

validator = MyRequestValidator()
oauth_server = WebApplicationServer(validator)


# ====================================================
# curl -H 'Accept: application/json' localhost:8081/ -d '{"a":"b"}' -H "Content-Type: application/json" -H "Authorization: Bearer 123abc"
# http://localhost:8081/authorize?client_id=0123456789abcdef&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fprivate&response_type=code&scope=base

def report_init(page, protocol, webinput):
    print(" {page} {protocol} ".format(page=page, protocol=protocol).center(50, '-'))
    print("SESSION ID: {0}".format(web.ctx.environ.get('HTTP_COOKIE', 'unknown')))
    print("SESSION KEYS: {0}".format(session.keys()))
    print("SESSION: {0}".format(dict(session)))
    print("WEB INPUT: {0}".format(webinput))
    print("-"*50)
    print("")


class Home(object):

    def is_remembered(self):
        print("attempting to remember user")
        cookie = web.cookies().get('rememberme')
        if not cookie:
            print("No cookie found.")
            return False
        try:
            account, token, _hash = cookie.split(":")
            users = Users(common.db)
            user = users.get_by_id(account)
            if user:
                print("memory of user found")
                saved_token = user.remember_token
                saved_key = user.secret_key
                dk = hashlib.pbkdf2_hmac('sha256', "{0}:{1}".format(account, saved_token), saved_key, 100000)
                ascii_hash = binascii.hexlify(dk)
                matches = hmac.compare_digest(cookie, "{0}:{1}:{2}".format(account, saved_token, ascii_hash))
                if matches:
                    print("user codes match! User is remembered")
                    return user
        except:
            traceback.print_exc()
        return False

    def is_logged_in(self):
        return "logged_in" in session and session['logged_in'] is True and "name" in session

    def GET(self):
        data = web.input()
        report_init("HOME", "GET", data)

        # check if the user is currently logged in
        is_logged_in = self.is_logged_in()

        # if not logged in and they had checked "stay logged in", automatically log in the user.
        if not is_logged_in:
            user = self.is_remembered()
            if user:
                session['logged_in'] = True
                session['name'] = user.name
                is_logged_in = True

        # if logged in, get user's name.
        if is_logged_in:
            name = session['name']
        else:
            name = ""

        return common.render.home(is_logged_in, name)


class Login(object):

    def remember_me(self, account_id):
        print("Saving, for remembering later.")
        token = common.generate_salt(32)
        secret_key = common.generate_salt(32)
        self.users.storeRememberToken(account_id, token, secret_key)
        cookie_text = "{0}:{1}".format(account_id, token)
        dk = hashlib.pbkdf2_hmac('sha256', cookie_text, secret_key, 100000)
        ascii_hash = binascii.hexlify(dk)
        cookie_text = "{0}:{1}".format(cookie_text, ascii_hash)
        duration = 31536000  # 60*60*24*365 # 1 year
        # TODO: set secure=True to require HTTPS
        # TODO: does the domain or path need to be set?
        web.setcookie('rememberme', cookie_text, expires=duration, domain="localhost", path="/")
        # setcookie(name, value, expires='', domain=None, secure=False, httponly=False, path=None):

    def get_user(self, data):
        try:
            account = data['account']
            email = data['email']
            password = data['password']
        except KeyError:
            return None

        self.users = Users(common.db)
        user = self.users.get(email, password)
        return user

    def POST(self):
        data = web.input()
        report_init("LOGIN", "POST", data)

        user = self.get_user(data)
        if user:
            session['name'] = user['name']
            session['logged_in'] = True
            if data.get('remember', " ") == "True":
                self.remember_me(user['id'])
        web.seeother("/")


class Logout(object):
    def GET(self):
        data = web.input()
        report_init("LOGOUT", "GET", data)
        web.setcookie('rememberme', "", expires=-1)
        session.kill()
        web.seeother("/")

    def POST(self):
        print(" LOGOUT POST ".center(50, '-'))
        self.GET()


class Authorize(object):
    def __init__(self):
        print("assigning server")
        self._authorization_endpoint = oauth_server
        print("finished init")

    def GET(self):
        """
        There are many bits of information the OAuth server can ingest.
        These bits of information are received either through the uri query string,
        Or the body (data) of the request.
        See `Request` constructor in oauthlib/common.py
        Minimum required are: [client_id, redirect_uri, response_type, scope]
            "access_token": None,
            "client": None,
            "client_id": None,
            "client_secret": None,
            "code": None,
            "extra_credentials": None,
            "grant_type": None,
            "redirect_uri": None,
            "refresh_token": None,
            "request_token": None,
            "response_type": None,
            "scope": None,
            "scopes": None,
            "state": None,
            "token": None,
            "user": None,
            "token_type_hint": None,

            # OpenID Connect
            "response_mode": None,
            "nonce": None,
            "display": None,
            "prompt": None,
            "claims": None,
            "max_age": None,
            "ui_locales": None,
            "id_token_hint": None,
            "login_hint": None,
            "acr_values": None
        :return:
        """
        data = web.input()
        report_init("AUTHORIZE", "GET", data)
        uri = "{scheme}://{host}{port}{path}".format(
            scheme=web.ctx.env.get('wsgi.url_scheme', 'http'),
            host=web.ctx.env['SERVER_NAME'],
            port=':{0}'.format(web.ctx.env['SERVER_PORT']),
            path=web.ctx.env['REQUEST_URI']
        )
        http_method = web.ctx.environ["REQUEST_METHOD"]
        body = web.ctx.get('data', '')
        headers = web.ctx.env.copy()
        headers.pop("wsgi.errors", None)
        headers.pop("wsgi.input", None)

        try:
            scopes, credentials = self._authorization_endpoint.validate_authorization_request(
                uri, http_method, body, headers)

            # Not necessarily in session but they need to be
            # accessible in the POST view after form submit.

            # NOTE: I need to remove "request" because it stores custom data structures
            # and fails to be properly pickled into the session storage
            credentials.pop("request", None)
            print(credentials)
            # session['oauth2_credentials'] = credentials

            # You probably want to render a template instead.
            return common.render.authorize(scopes, credentials)

        # Errors that should be shown to the user on the provider website
        except errors.FatalClientError as e:
            return response_from_error(e)

        # Errors embedded in the redirect URI back to the client
        # except errors.OAuth2Error as e:
        #    return HttpResponseRedirect(e.in_uri(e.redirect_uri))

        # Something else went wrong.
        except Exception:
            print(" Something went wrong. ".center(70, '='))
            traceback.print_exc()
        return "reached end of GET code"

    def POST(self):
        test_scopes = []
        data = web.input(scopes=test_scopes)
        report_init("AUTHORIZE", "POST", data)
        uri = "{scheme}://{host}{port}{path}".format(
            scheme=web.ctx.env.get('wsgi.url_scheme', 'http'),
            host=web.ctx.env['SERVER_NAME'],
            port=':{0}'.format(web.ctx.env['SERVER_PORT']),
            path=web.ctx.env['REQUEST_URI']
        )
        http_method = web.ctx.environ["REQUEST_METHOD"]
        body = web.ctx.get('data', '')
        headers = web.ctx.env.copy()
        headers.pop("wsgi.errors", None)
        headers.pop("wsgi.input", None)

        # The scopes the user actually authorized, i.e. checkboxes
        # that were selected.
        scopes = data.get('scopes', [])

        print("Scopes: {0}".format(repr(scopes)))

        # Extra credentials we need in the validator
        # credentials = {'user': request.user}
        # TODO: what goes here?
        credentials = {'user': 'temp'}

        # The previously stored (in authorization GET view) credentials
        # probably contains: 'state', 'redirect_uri', 'response_type', 'client_id'
        credentials.update(data)

        try:
            print("creating authorization response\n")
            headers, body, status = self._authorization_endpoint.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials)
            print("\nauthorization response created")
            if headers.keys() == ['Location'] and status in (302, 303):
                print("Redirecting to {0}".format(headers['Location']))
                raise web.seeother(headers['Location'], absolute=True)
            else:
                return response_from_return(headers, body, status)

        except errors.FatalClientError as e:
            return response_from_error(e)


class Token(object):
    def __init__(self):
        self._authorization_endpoint = oauth_server

    def GET(self):
        data = web.input()
        report_init("TOKEN", "GET", data)
        return common.render.dummy()

    def POST(self):
        data = web.input()
        report_init("TOKEN", "POST", data)
        return common.render.dummy()


def response_from_return(headers, body, status):
    print("doing response_from_return(...)")
    print("  headers: {0}".format(headers))
    print("  body: {0}".format(body))
    print("  status: {0}".format(status))
    # raise web.seeother("http://www.google.ca")
    raise web.HTTPError(status, headers, body)


def response_from_error(e):
    raise web.BadRequest('<h1>Bad Request</h1><p>Error is: {0}</p>'.format(e.description))


if __name__ == "__main__":
    app.run()
