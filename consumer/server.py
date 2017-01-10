import json
import web
import urllib
import urllib2
import base64
import os

urls = (
    '/', 'Public',  # Omit the overview page and go straight to map (no content in overview anyway)
    '/public', 'Public',
    '/private', 'Private',
    '/login', 'Login',
    '/logout', 'Logout',
)

# This is the URL we'll send the user to first to get their authorization
authorizeURL = 'localhost:8081/authorize'

# This is the endpoint our server will request an access token from
tokenURL = 'localhost:8081/token'


app = web.application(urls, globals())

if web.config.get('_session') is None:
    session = web.session.Session(app, web.session.DiskStore('sessions'), {'count': 0})
    web.config._session = session
else:
    session = web.config._session

render = web.template.render('./')

# ====================================================


def apiRequest(url, post=False, headers=None):
    if headers is None:
        headers = []

    # $ch = curl_init($url);
    # curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);

    if post:
        # curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
        pass

    headers.append('Accept: application/json')

    if 'access_token' in session:
        headers.append('Authorization: Bearer {0}'.format(session['access_token']))

    # curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    # $response = curl_exec($ch);
    response = '{"error": "response not retreived"}'

    return json.loads(response)

def getRequest(url, headers=None, args=None):
    """
    :param url:  The url to send the request to.  e.g.  https://example.org/test
    :param headers:  dictionary of headers. e.g. {"Accepts": "text/html"}
    :param args: dictionary of GET parameters to urlencode and append to the url
    :return: the server response
    """

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
    :param args: dictionary of GET parameters to urlencode and append to the url
    :return: the server response
    """

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
    response = urllib2.urlopen(request, args).read()

    return response



class Public(object):
    def GET(self):
        print("PUBLIC GET".center(50, '='))
        GET_data = web.input()
        return render.public_page()

    def POST(self):
        print("PUBLIC POST".center(50, '='))
        GET_data = web.input()
        return render.public_page()


class Private(object):
    def retrieve_key(self, GET_data):
            # Verify the state matches our stored state
            if 'state' not in GET_data or GET_data['state'] != session['state']:
                print("State salt does not match.")
                raise web.seeother("/public")

            # Exchange the auth code for a token
            params = {
                'client_id': "12345",
                'client_secret': 'abcde',
                'redirect_uri': 'http://localhost:8080/private',
                'state': session['state'],
                'code': GET_data['code']
            }
            token = postRequest(tokenURL, args=params)
            print("token received:\n{0}".format(token))
            session['access_token'] = token

            raise web.seeother("/private")

    def GET(self):
        print("PRIVATE GET".center(50, '='))
        GET_data = web.input()

        if 'code' in GET_data:
            self.retrieve_key(GET_data)

        if 'access_token' in session:
            return render.private_page()
        else:
            raise web.seeother("/public")

    def POST(self):
        print("PRIVATE POST".center(50, '='))
        GET_data = web.input()


class Login(object):
    def GET(self):
        print("LOGIN GET".center(50, '='))
        GET_data = web.input()

        # Generate a random hash and store in the session for security
        seq = os.urandom(48)
        enc_seq = base64.b64encode(seq)
        session['state'] = enc_seq
        session.pop('access_token', None)

        params = {
            'client_id': "12345",
            'redirect_uri': 'http://localhost:8080/private',
            'scope': 'user',
            'state': session['state']
        }

        # Redirect the user to the authorization page
        qstring = urllib.urlencode(params)
        raise web.seeother("{0}?{1}".format(authorizeURL, qstring))

    def POST(self):
        print("LOGIN POST".center(50, '='))
        GET_data = web.input()

class Logout(object):
    def GET(self):
        print("LOGOUT GET".center(50, '='))
        session.kill()
        raise web.seeother("/public")

    def POST(self):
        print("LOGOUT POST".center(50, '='))
        self.GET()
        raise web.seeother("/public")


# Manage routing from here. Regex matches URL and chooses class by name


if __name__ == "__main__":
    app.run()
