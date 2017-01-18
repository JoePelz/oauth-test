import inspect
import common
from oauthlib.oauth2 import RequestValidator
from oauthlib.oauth2.rfc6749.clients import WebApplicationClient


class MyRequestValidator(RequestValidator):
    # Ordered roughly in order of appearance in the authorization grant flow

    # Pre- and post-authorization.

    def validate_client_id(self, app_id, request, *args, **kwargs):
        # Simple validity check, does client exist? Not banned?
        print("validate app id")
        app = common.applications.exists(app_id)
        return app

    def validate_redirect_uri(self, app_id, redirect_uri, request, *args, **kwargs):
        # Is the client allowed to use the supplied redirect_uri? i.e. has
        # the client previously registered this EXACT redirect uri.
        print("validate redirect uri")
        app = common.applications.get(app_id)
        uris = app.redirect_uris.split(' ')
        return redirect_uri and redirect_uri in uris

    def get_default_redirect_uri(self, app_id, request, *args, **kwargs):
        # The redirect used if none has been supplied.
        # Prefer your clients to pre register a redirect uri rather than
        # supplying one on each authorization request.
        print("get default redirect uri")
        app = common.applications.get(app_id)
        return app.default_redirect_uri

    def validate_scopes(self, app_id, scopes, client, request, *args, **kwargs):
        # Is the client allowed to access the requested scopes?
        print("validate_scopes")
        app = common.applications.get(app_id)
        app_scopes = app.scopes.split(' ')
        return all([requested_scope in app_scopes for requested_scope in scopes])

    def get_default_scopes(self, app_id, request, *args, **kwargs):
        # Scopes a client will authorize for if none are supplied in the
        # authorization request.
        print("get_default_scopes")
        app = common.applications.get(app_id)
        return app.default_scopes

    def validate_response_type(self, app_id, response_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of response type, the
        # one associated with their one allowed grant type.
        # In this case it must be "code".
        print("validate response type")
        app = common.applications.get(app_id)
        return response_type == app.response_type

    # Post-authorization

    def save_authorization_code(self, app_id, code, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.redirect_uri
        # request.client, request.state and request.user (the last is passed in
        # post_authorization credentials, i.e. { 'user': request.user}.
        print('save_authorization_code')
        print("app_id is {0}".format(app_id))
        print("code is {0}".format(code))
        print("request is {0}".format(request))
        code_string = code['code']
        state = code.get('state', '')
        common.authorization_codes.set(
            app_id=app_id,
            user_id=request.user,
            code=code_string,
            scopes=' '.join(request.scopes),
            state=state,
            redirect_uri=request.redirect_uri)

    # Token request

    def authenticate_client(self, request, *args, **kwargs):
        # Whichever authentication method suits you, HTTP Basic might work
        # TODO: generate secret for each client app. Use app id and secret to authenticate client.
        # see https://github.com/evonove/django-oauth-toolkit/blob/master/oauth2_provider/oauth2_validators.py#L51
        print("authenticate_client")
        authenticated = True

        app_secret = request.client_secret
        app_id = request.client_id
        auth_code = request.code

        # make sure client_secret matches client_id
        if authenticated:
            authenticated = common.applications.secret_matches_id(app_id, app_secret)

        # store credentials (This is a side effect, but OAuthLib raises an exception if this isn't done here.)
        if authenticated:
            request.client = WebApplicationClient(app_id, code=auth_code, client_secret=app_secret)
        return authenticated

    def authenticate_client_id(self, app_id, request, *args, **kwargs):
        # Don't allow public (non-authenticated) clients
        return False

    def validate_code(self, app_id, code, client, request, *args, **kwargs):
        # Validate the code belongs to the client. Add associated scopes,
        # state and user to request.scopes and request.user.
        print("validate_code")

        # App_id has been confirmed. does the code match the app?
        # make sure the code applies to the (previously authenticated) client/app.
        authorization = common.authorization_codes.get(code)
        valid = app_id == authorization.app_id

        # make sure the granted state/user/scopes/redirect are all saved in the request object
        # This is a side effect, but required by the library.
        if valid:
            request.scopes = authorization.scopes.split(' ')
            request.user = authorization.user_id
            request.state = authorization.state
            request.client.auth_redirect_uri = authorization.redirect_uri

        return valid

    def confirm_redirect_uri(self, app_id, code, redirect_uri, client, *args, **kwargs):
        # You did save the redirect uri with the authorization code right?
        print("confirm_redirect_uri")

        requested_uri = redirect_uri
        authorized_uri = client.auth_redirect_uri

        confirmed = requested_uri == authorized_uri

        return confirmed

    def validate_grant_type(self, app_id, grant_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of grant.
        # In this case, it must be "authorization_code" or "refresh_token"
        return grant_type in ['authorization_code', 'refresh_token']

    def save_bearer_token(self, token, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.user and
        # request.client. The two former will be set when you validate
        # the authorization code. Don't forget to save both the
        # access_token and the refresh_token and set expiration for the
        # access_token to now + expires_in seconds.

        # may actually be more complicated than this...
        # https://github.com/evonove/django-oauth-toolkit/blob/master/oauth2_provider/oauth2_validators.py#L307

        scope = token['scope']
        access_token_code = token['access_token']
        refresh_token_code = token.get('refresh_token', None)

        common.bearer_tokens.set(
            application_id=request.client.client_id,
            user=request.user,
            scopes=scope,
            access_token=access_token_code,
            refresh_token=refresh_token_code)

    def invalidate_authorization_code(self, app_id, code, request, *args, **kwargs):
        # Authorization codes are use once, invalidate it when a Bearer token
        # has been acquired.
        common.authorization_codes.remove(code)

    # Protected resource request

    def validate_bearer_token(self, token, scopes, request):
        # Remember to check expiration and scope membership
        # TODO: Remember to check expiration and scope membership
        print("validate_bearer_token")
        db_token = common.bearer_tokens.get_access(token)
        return db_token and all([scope in db_token.scopes for scope in scopes])

    # Token refresh request

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # Obtain the token associated with the given refresh_token and
        # return its scopes, these will be passed on to the refreshed
        # access token if the client did not specify a scope during the
        # request.
        print("get_original_scopes")
        db_token = common.bearer_tokens.get_access(refresh_token)
        scopes = db_token.scopes.split(' ')
        return scopes

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        raise NotImplemented("{0} not implemented".format(inspect.currentframe().f_code.co_name))

    def get_id_token(self, token, token_handler, request):
        raise NotImplemented("{0} not implemented".format(inspect.currentframe().f_code.co_name))

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        raise NotImplemented("{0} not implemented".format(inspect.currentframe().f_code.co_name))

    def validate_user_match(self, id_token_hint, scopes, claims, request):
        print("validate_user_match")
        raise NotImplemented("{0} not implemented".format(inspect.currentframe().f_code.co_name))

    def validate_silent_login(self, request):
        raise NotImplemented("{0} not implemented".format(inspect.currentframe().f_code.co_name))

    def validate_silent_authorization(self, request):
        raise NotImplemented("{0} not implemented".format(inspect.currentframe().f_code.co_name))

    def validate_user(self, username, password, client, request, *args, **kwargs):
        raise NotImplemented("{0} not implemented".format(inspect.currentframe().f_code.co_name))
