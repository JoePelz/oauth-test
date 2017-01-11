class BearerToken(object):
    def __init__(self, db):
        self.db = db
        self.table = "BearerToken"

    def remove(self, client_id, user):
        qvars = {
            'cid': client_id,
            'uid': user
        }
        num_deleted = self.db.delete(self.table, where="client_id=$cid AND user=$uid", vars=qvars, limit=1)
        return num_deleted

    def set(self, client_id, user, scopes, access_token, refresh_token):
        self.remove(client_id, user)
        self.db.insert(self.table,
                       client_id=client_id,
                       user=user,
                       scopes=scopes,
                       access_token=access_token,
                       refresh_token=refresh_token)
        return

    def get_access(self, access_token):
        qvars = {
            'act': access_token
        }
        rows = self.db.select(self.table, 'access_token=$act', vars=qvars, limit=1)
        return rows.first()

    def get_refresh(self, refresh_token):
        qvars = {
            'refr': refresh_token
        }
        rows = self.db.select(self.table, 'refresh_token=$refr', vars=qvars, limit=1)
        return rows.first()