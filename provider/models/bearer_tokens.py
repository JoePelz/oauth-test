class BearerTokens(object):
    def __init__(self, db):
        self.db = db
        self.table = "BearerTokens"

    def remove(self, application_id, user):
        qvars = {
            'aid': application_id,
            'uid': user
        }
        num_deleted = self.db.delete(self.table, where="app_id=$aid AND user_id=$uid", vars=qvars)
        return num_deleted

    def set(self, application_id, user, scopes, access_token, refresh_token):
        self.remove(application_id, user)
        self.db.insert(self.table,
                       app_id=application_id,
                       user_id=user,
                       scopes=scopes,
                       access_token=access_token,
                       refresh_token=refresh_token)
        return

    def get_access(self, access_token):
        qvars = {
            'act': access_token
        }
        rows = self.db.select(self.table, where='access_token=$act', vars=qvars, limit=1)
        return rows.first()

    def get_refresh(self, refresh_token):
        qvars = {
            'refr': refresh_token
        }
        rows = self.db.select(self.table, where='refresh_token=$refr', vars=qvars, limit=1)
        return rows.first()