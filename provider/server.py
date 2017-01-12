import traceback
import pprint
import web
import constants
from request_validator import MyRequestValidator
from oauthlib.oauth2 import WebApplicationServer
import oauthlib.oauth2.rfc6749.errors as errors

import logging
import sys
log = logging.getLogger('oauthlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)


app = web.application(constants.urls, globals())

validator = MyRequestValidator()
server = WebApplicationServer(validator)

#if web.config.get('_session') is None:
#    session = web.session.Session(app, web.session.DiskStore('sessions'), {'count': 0})
#    web.config._session = session
#else:
#    session = web.config._session
web.config.debug = False
session = web.session.Session(app, web.session.DiskStore('sessions'), {'count': 0})

# ====================================================
# curl -H 'Accept: application/json' localhost:8080/ -d '{"a":"b"}' -H "Content-Type: application/json" -H "Authorization: Bearer 123abc"
# http://localhost:8081/authorize?client_id=0123456789abcdef&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fprivate&response_type=code&scope=base
class Dummy(object):
    def GET(self):
        print("DUMMY GET".center(50, '='))
        # GET_data = web.input()
        return constants.render.dummy()

    def POST(self):
        print("DUMMY POST".center(50, '='))
        # GET_data = web.input()
        return constants.render.dummy()

class Authorize(object):
    def __init__(self):
        print("assigning server")
        self._authorization_endpoint = server
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
        print("AUTHORIZE GET".center(50, '='))
        uri = "{scheme}://{host}{port}{path}".format(
            scheme = web.ctx.env.get('wsgi.url_scheme', 'http'),
            host = web.ctx.env['SERVER_NAME'],
            port = ':{0}'.format(web.ctx.env['SERVER_PORT']),
            path = web.ctx.env['REQUEST_URI']
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
            session['oauth2_credentials'] = credentials

            # You probably want to render a template instead.
            return constants.render.authorize("0123456789abcdef", scopes)

        # Errors that should be shown to the user on the provider website
        except errors.FatalClientError as e:
            return response_from_error(e)

        # Errors embedded in the redirect URI back to the client
        #except errors.OAuth2Error as e:
        #    return HttpResponseRedirect(e.in_uri(e.redirect_uri))

        # Something else went wrong.
        except Exception:
            print(" Something went wrong. ".center(70, '='))
            traceback.print_exc()
        return "reached end of GET code"

    def POST(self):
        print("AUTHORIZE POST".center(50, '='))
        uri = "{scheme}://{host}{port}{path}".format(
            scheme = web.ctx.env.get('wsgi.url_scheme', 'http'),
            host = web.ctx.env['SERVER_NAME'],
            port = ':{0}'.format(web.ctx.env['SERVER_PORT']),
            path = web.ctx.env['REQUEST_URI']
        )
        http_method = web.ctx.environ["REQUEST_METHOD"]
        body = web.ctx.get('data', '')
        headers = web.ctx.env.copy()
        headers.pop("wsgi.errors", None)
        headers.pop("wsgi.input", None)

        # The scopes the user actually authorized, i.e. checkboxes
        # that were selected.
        POST_data = web.input()
        print("POST data: ")
        pprint.pprint(POST_data)
        scopes = POST_data.get('scopes')
        if scopes:
            scopes = scopes.split(' ')
            print("Scopes: {0}".format(scopes))
        else:
            print("No scopes recorded.")
            scopes = []

        # Extra credentials we need in the validator
        # credentials = {'user': request.user}
        # TODO: what goes here?
        credentials = {'user': 'temp'}

        # The previously stored (in authorization GET view) credentials
        credentials.update(session.get('oauth2_credentials', {}))

        try:
            headers, body, status = self._authorization_endpoint.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials)
            if headers.keys() == ['Location'] and status == 303:
                print("Redirecting to {0}".format(headers['Location']))
                raise web.seeother(headers['Location'], absolute=True)
            else:
                return response_from_return(headers, body, status)

        except errors.FatalClientError as e:
            return response_from_error(e)

class Token(object):
    def __init__(self):
        self._authorization_endpoint = server

    def GET(self):
        print("TOKEN GET".center(50, '='))
        return constants.render.dummy()

    def POST(self):
        print("TOKEN POST".center(50, '='))
        return constants.render.dummy()


def response_from_return(headers, body, status):
    print("doing response_from_return(...)")
    print("  headers: {0}".format(headers))
    print("  body: {0}".format(body))
    print("  status: {0}".format(status))
    # raise web.seeother("http://www.google.ca")
    raise web.HTTPError(status, headers, body)

def response_from_error(e):
    raise web.BadRequest('Evil client is unable to send a proper request. Error is: ' + e.description)


if __name__ == "__main__":
    app.run()
