import pprint
import traceback
from oauthlib.oauth2 import WebApplicationServer
import oauthlib.oauth2.rfc6749.errors as errors
import logging
import sys
import web
web.config.debug = False
import constants
import common
from request_validator import MyRequestValidator
from models.users import Users
from models.subscriptions import Subscriptions
from models.applications import Applications

# enable logging, while under development
log = logging.getLogger('oauthlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)

app = web.application(constants.urls, globals())
session = web.session.Session(app, common.session_store)

validator = MyRequestValidator()
oauth_server = WebApplicationServer(validator)



def report_init(page, protocol, webinput):
    print(" {page} {protocol} ".format(page=page, protocol=protocol).center(50, '-'))
    print("SESSION ID: {0}".format(web.ctx.environ.get('HTTP_COOKIE', 'unknown')))
    print("SESSION KEYS: {0}".format(session.keys()))
    print("SESSION: {0}".format(dict(session)))
    print("WEB INPUT: {0}".format(webinput))
    print("-"*50)
    print("")


class Home(object):
    def __init__(self):
        self.users = Users(common.db)
        self.subscriptions = Subscriptions(common.db)
        self.applications = Applications(common.db)

    def get_user_id(self):
        if "logged_in" in session and session['logged_in'] is True and "user_id" in session:
            return session['user_id']

        cookie = web.cookies().get(constants.REMEMBER_COOKIE_NAME)
        if cookie:
            cookie_parts = cookie.split(":")
            if len(cookie_parts) == 3:
                uid, token, hash = cookie_parts
                if self.users.validate_login_cookie(uid, token, hash):
                    session['logged_in'] = True
                    session['user_id'] = uid
                    return uid
        return None

    def get_user_data(self, user_id):
        user = dict(self.users.get_by_id(user_id))

        # accessible apps
        subs = self.subscriptions.get_by_user(user_id)
        user['subscriptions'] = map(dict, subs)

        # ownded apps
        apps = self.applications.get_by_owner(user_id)
        user['apps'] = apps

        return user

    def GET(self):
        data = web.input()
        report_init("HOME", "GET", data)

        user_id = self.get_user_id()
        is_logged_in = bool(user_id)
        if is_logged_in:
            user = self.get_user_data(user_id)
        else:
            user = None

        return common.render.home(is_logged_in, user)


class Login(object):
    def __init__(self):
        self.users = Users(common.db)

    def save_cookie(self, account_id):
        print("Saving, for remembering later.")
        cookie_text = self.users.get_login_cookie(account_id)
        duration = 31536000  # 60*60*24*365 # 1 year-ish
        # TODO: set secure=True to require HTTPS
        # TODO: does the domain or path need to be set?
        web.setcookie(constants.REMEMBER_COOKIE_NAME, cookie_text, expires=duration, domain="auth.local", path="/")
        # setcookie(name, value, expires='', domain=None, secure=False, httponly=False, path=None):

    def get_user(self, data):
        try:
            account = data['account']
            email = data['email']
            password = data['password']
        except KeyError:
            return None

        user = self.users.get(email, password)
        return user

    def POST(self):
        data = web.input()
        report_init("LOGIN", "POST", data)

        user = self.get_user(data)
        if user:
            session['user_id'] = user['id']
            session['logged_in'] = True
            if data.get('remember', " ") == "True":
                self.save_cookie(user['id'])
        web.seeother("/")


class Logout(object):
    def GET(self):
        data = web.input()
        report_init("LOGOUT", "GET", data)
        web.setcookie(constants.REMEMBER_COOKIE_NAME, "", expires=-1, domain="auth.local", path="/")
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
            print("")
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
        pprint.pprint(headers)
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
