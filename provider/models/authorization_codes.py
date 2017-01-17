class AuthorizationCodes(object):
    def __init__(self, db):
        self.db = db
        self.table = "AuthorizationCodes"

    def remove(self, application_id, code):
        qvars = {
            'aid': application_id,
            'code': code
        }
        num_deleted = self.db.delete(self.table, where="app_id=$aid AND code=$code", vars=qvars)
        return num_deleted

    def set(self, application_id, user_id, scopes, code, state, redirect_uri):
        self.remove(application_id, code)
        self.db.insert(self.table,
                       app_id=application_id,
                       code=code,
                       user_id=user_id,
                       scopes=scopes,
                       state=state,
                       redirect_uri=redirect_uri)
        return

    def match(self, **keys):
        where = " AND ".join(map("{0}=${0}".format, keys.keys()))
        qvars = keys
        rows = self.db.select(self.table, where=where, vars=qvars)
        return rows.first()