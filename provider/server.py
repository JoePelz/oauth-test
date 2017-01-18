import traceback
from oauthlib.oauth2 import WebApplicationServer
import oauthlib.oauth2.rfc6749.errors as errors
import logging
import sys
import web
web.config.debug = False
from web.wsgiserver import CherryPyWSGIServer
import constants
import common
from request_validator import MyRequestValidator

# enable logging, while under development
log = logging.getLogger('oauthlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)

# openssl req -x509 -sha256 -nodes -newkey rsa:2048 -days 365 -keyout localhost.key -out localhost.crt
CherryPyWSGIServer.ssl_certificate = "./localhost.crt"
CherryPyWSGIServer.ssl_private_key = "./localhost.key"

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

    def get_user_id(self):
        if "logged_in" in session and session['logged_in'] is True and "user_id" in session:
            return session['user_id']

        cookie = web.cookies().get(constants.REMEMBER_COOKIE_NAME)
        if cookie:
            cookie_parts = cookie.split(":")
            if len(cookie_parts) == 3:
                uid, token, hash = cookie_parts
                if common.users.validate_login_cookie(uid, token, hash):
                    session['logged_in'] = True
                    session['user_id'] = uid
                    return uid
        return None

    def get_user_data(self, user_id):
        user = dict(common.users.get_by_id(user_id))

        # accessible apps
        subs = common.subscriptions.get_by_user(user_id)
        user['subscriptions'] = map(dict, subs)

        # owned apps
        apps = common.applications.get_by_owner(user_id)
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
    def save_cookie(self, account_id):
        print("Saving, for remembering later.")
        cookie_text = common.users.get_login_cookie(account_id)
        duration = 31536000  # 60*60*24*365 # 1 year-ish
        # TODO: what is httponly? needed?
        # TODO: does the domain or path need to be set?
        web.setcookie(constants.REMEMBER_COOKIE_NAME, cookie_text, expires=duration, domain="auth.local", path="/", secure=True)
        # setcookie(name, value, expires='', domain=None, secure=False, httponly=False, path=None):

    def get_user(self, data):
        try:
            account = data['account']
            email = data['email']
            password = data['password']
        except KeyError:
            return None

        user = common.users.get(email, password)
        return user

    def GET(self):
        data = web.input()
        report_init("LOGIN", "GET", data)
        # show login page
        return common.render.login()


    def POST(self):
        data = web.input()
        report_init("LOGIN", "POST", data)

        user = self.get_user(data)
        if user:
            session['user_id'] = user['id']
            session['logged_in'] = True
            if data.get('remember', " ") == "True":
                self.save_cookie(user['id'])

        # send them back where they came from
        destination = '/'
        if 'login_redirect' in session:
            destination = session['login_redirect']
        print("redirecting to {0}".format(destination))
        web.seeother(destination)


class Logout(object):
    def GET(self):
        data = web.input()
        report_init("LOGOUT", "GET", data)
        web.setcookie(constants.REMEMBER_COOKIE_NAME, "", expires=-1, domain="auth.local", path="/")

        destination = '/'
        if 'login_redirect' in session:
            destination = session['login_redirect']

        session.kill()
        print("redirecting to {0}".format(destination))
        web.seeother(destination)

    def POST(self):
        print(" LOGOUT POST ".center(50, '-'))
        self.GET()


class Authorize(object):
    def __init__(self):
        print("assigning server")
        self._authorization_endpoint = oauth_server
        print("finished init")

    def get_user_id(self):
        if "logged_in" in session and session['logged_in'] is True and "user_id" in session:
            return session['user_id']

        cookie = web.cookies().get(constants.REMEMBER_COOKIE_NAME)
        if cookie:
            cookie_parts = cookie.split(":")
            if len(cookie_parts) == 3:
                uid, token, hash = cookie_parts
                if common.users.validate_login_cookie(uid, token, hash):
                    session['logged_in'] = True
                    session['user_id'] = uid
                    return uid
        return None

    def GET(self):
        data = web.input()
        report_init("AUTHORIZE", "GET", data)
        # TODO: host should be web.ctx.env['SERVER_NAME']
        # but that doesn't work for testing here.
        uri = "{scheme}://{host}{port}{path}".format(
            scheme=web.ctx.env.get('wsgi.url_scheme', 'http'),
            host='auth.local',  # web.ctx.env['SERVER_NAME'],
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

            # Store some important information for later.
            # Not necessarily in session but they need to be
            # accessible in the POST view after form submit.
            # NOTE: I need to remove "request" because it contains custom data structures
            # and fails to be properly pickled into the session storage
            credentials.pop("request", None)
            session['oauth2_credentials'] = credentials
            session['oauth2_scopes'] = scopes
            session['login_redirect'] = uri

            # Display authorization page
            user_id = self.get_user_id()
            if user_id:
                user = common.users.get_by_id(user_id)
                app = common.applications.get(credentials['client_id'])
                # if logged in, display authorization page
                credentials['user'] = user_id
                return common.render.authorize(user.name, app.nicename)
            else:
                # otherwise, display login page
                print("redirecting to /login")
                raise web.seeother("/login")

        # Errors that should be shown to the user on the provider website
        except errors.FatalClientError as e:
            return response_from_error(e)
        # Errors embedded in the redirect URI back to the client
        except errors.OAuth2Error as e:
            raise web.seeother(e.in_uri(e.redirect_uri))

        # Something else went wrong.
        except Exception:
            print(" Something went wrong. ".center(70, '='))
            traceback.print_exc()
        return "reached end of GET code"

    def POST(self):
        data = web.input()
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

        # Did the user approve access?
        approved = data.get('approved') == "yes"

        # TODO: What if approved is not True?
        # Extra credentials we need in the validator
        credentials = {'user': self.get_user_id()}

        # The previously stored (in authorization GET view) credentials
        # probably contains: 'state', 'redirect_uri', 'response_type', 'client_id'
        credentials.update(session.get('oauth2_credentials', {}))
        scopes = session.get('oauth2_scopes', [])

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
        self._token_endpoint = oauth_server

    def GET(self):
        data = web.input()
        report_init("TOKEN", "GET", data)
        print("Error. POST expected.")
        return common.render.dummy()

    def POST(self):
        data = web.input()
        report_init("TOKEN", "POST", data)

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
        headers = {
            'CONTENT_TYPE': 'application/x-www-form-urlencoded;charset=UTF-8'
        }

        # If you wish to include request specific extra credentials for
        # use in the validator, do so here.
        credentials = {
            #'foo': 'bar'
        }

        headers, body, status = self._token_endpoint.create_token_response(
            uri, http_method, body, headers, credentials)

        # All requests to /token will return a json response, no redirection.
        return response_from_return(headers, body, status)


def response_from_return(headers, body, status):
    print("response_from_return(...)")
    print("  headers: {0}".format(str(headers)[:50]))
    print("  body: {0}".format(str(body)[:50]))
    print("  status: {0}".format(status))
    # raise web.HTTPError(status, headers, body)
    raise web.HTTPError('200 OK', headers, body)


def response_from_error(e):
    raise web.BadRequest('<h1>Bad Request</h1><p>Error is: {0}</p>'.format(e.description))


if __name__ == "__main__":
    app.run()
