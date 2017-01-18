import time

class AuthorizationCodes(object):
    def __init__(self, db):
        self.db = db
        self.table = "AuthorizationCodes"

    def remove_all_expired(self):
        qvars = {
            'now': int(time.time())
        }
        return self.db.delete(self.table, where='expiration_time<=$now', vars=qvars)

    def remove(self, auth_code):
        qvars = {
            'code': auth_code
        }
        num_deleted = self.db.delete(self.table, where="code=$code", vars=qvars)
        return num_deleted

    def set(self, app_id, user_id, scopes, code, state, redirect_uri):
        """

        :param app_id: string; id of the application to authorize
        :param user_id: string; id of the resource owner (user of the application)
        :param scopes: string; string representation of the 1+ access scopes being authorized.
        :param code: string; randomly generated code to authenticate browser
        :param state: string; salt that is saved and passed through unchanged
        :param redirect_uri: string; the redirect_uri to send the browser back to after authorization
        :return: None
        """
        #the authorization code table is expected to be active (adding/removing)
        # but always small. remove_all_expired() should be very cheap.
        self.remove_all_expired()
        self.remove(code)
        self.db.insert(self.table,
                       app_id=app_id,
                       code=code,
                       user_id=user_id,
                       scopes=scopes,
                       state=state,
                       redirect_uri=redirect_uri)
        return

    def is_expired(self, row):
        return int(row.expiration_time) <= (time.time())

    def get(self, auth_code):
        """
        Get the authorization data stored with a particular code for a particular app.
        :param auth_code: string; The unique authorization code to retrieve details about
        :return: the database row if a match is found, else None
        """
        qvars ={
            'code': auth_code
        }
        where = 'code=$code'
        rows = self.db.select(self.table, where=where, vars=qvars)
        row = rows.first()
        if row:
            self.remove(auth_code)
            if self.is_expired(row):
                return None
            else:
                return row
        return None
