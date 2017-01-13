class AuthorizationCode(object):
    def __init__(self, db):
        self.db = db
        self.table = "AuthorizationCode"

    def remove(self, application_id, code):
        qvars = {
            'aid': application_id,
            'code': code
        }
        num_deleted = self.db.delete(self.table, where="app_id=$aid AND code=$code", vars=qvars)
        return num_deleted

    def set(self, application_id, user, scopes, code, state, redirect_uri):
        self.remove(application_id, code)
        self.db.insert(self.table,
                       app_id=application_id,
                       user=user,
                       scopes=scopes,
                       code=code,
                       state=state,
                       redirect_uri=redirect_uri)
        return

    def match(self, **keys):
        where = " AND ".join(map("{0}=${0}".format, keys.keys()))
        qvars = keys
        rows = self.db.select(self.table, where, vars=qvars)
        return rows.first()