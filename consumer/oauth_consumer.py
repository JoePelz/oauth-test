import sys
import logging
import requests_oauthlib

log = logging.getLogger('oauthlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)
log = logging.getLogger('requests_oauthlib.oauth2_session')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)


class Authorization(object):
    def __init__(self, session, authorization_url, token_url, client_id, client_secret, default_redirect_uri, default_scope_requested):
        """
        :param session: A dict-like persistant storage to put tokens into.
        :param authorization_url: string/unicode; url to authorization endpoint.
        e.g. "https://auth.local:8081/authorize"
        :param token_url: string/unicode; url to token endpoint. e.g. "https://auth.local:8081/token"
        :param client_id: string/unicode; ID code to identify the application
        :param client_secret: string/unicode; secret code to authorize the application
        :param default_redirect_uri: string/unicode; The uri to redirect to on successful authorization.
        e.g. "https://app.local:8080/private"
        :param default_scope_requested: string/unicode; space-seperated permission-scopes requested.
        e.g. "profile_info friend_list"
        """
        self.storage = session
        self.token_name = "oauth_token"
        self.state_name = "oauth_state"
        self.auth_url = authorization_url
        self.token_url = token_url
        self.client_id = unicode(client_id)
        self.client_secret = unicode(client_secret)
        self.default_redirect_uri = unicode(default_redirect_uri)
        self.default_scope = unicode(default_scope_requested)

    def save_token(self, token):
        self.storage[self.token_name] = token

    def get_token(self):
        return self.storage.get(self.token_name, None)

    def save_state(self, state):
        self.storage[self.state_name] = state

    def get_state(self):
        return self.storage.get(self.state_name, None)

    def get_auth_url(self, redirect_uri=None, scope=None):
        redirect_uri = redirect_uri or self.default_redirect_uri
        scope = scope or self.default_scope

        oauth2_session = requests_oauthlib.OAuth2Session(
            self.client_id,
            redirect_uri=redirect_uri,
            scope=scope)

        authorization_url, state = oauth2_session.authorization_url(self.auth_url)
        self.save_state(state)
        return authorization_url

    def fetch_token(self, authorization_response_url, redirect_uri=None, scope=None):
        """
        :param authorization_response_url:  The full return url received after redirecting to
        the return value of get_auth_url().
        e.g. "https://app.local:8080/private?state=salt&code=secretAuthCode&scope=profileinfo%20friendslist"
        :param redirect_uri: string; the redirect_uri again. Reason unknown.
        :param scope: string; the scope again. Reason unknown.
        :return: dict; Authorization token (token_type, access_token, refresh_token, expires_at, scope)
        """
        redirect_uri = redirect_uri or self.default_redirect_uri
        scope = scope or self.default_scope

        oauth = requests_oauthlib.OAuth2Session(
            self.client_id, redirect_uri=redirect_uri, scope=scope
        )

        token = oauth.fetch_token(
            self.token_url,
            authorization_response=authorization_response_url,
            client_secret=self.client_secret,
            verify=False)


        self.save_token(token)

    def request(self, protected_url):
        extra = {
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        oauth = requests_oauthlib.OAuth2Session(
            self.client_id,
            token=self.get_token(),
            auto_refresh_url=self.token_url,
            auto_refresh_kwargs = extra,
            token_updater = self.save_token)

        r = oauth.get(protected_url)
        return r

    def has_valid_token(self):
        #TODO: contact server, validate token
        return True