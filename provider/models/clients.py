class Clients(object):
    def __init__(self, db):
        self.db = db
        self.table = "Client"

    def exists(self, client_id):
        qvars = {
            "cid": client_id
        }
        rows = self.db.select(self.table, what="1", where="client_id=$cid", vars=qvars, limit=1)
        client = rows.first()
        return client is not None

    def get(self, client_id):
        """
        :param client_id: unique id to search for
        :return: All user details of a client, if a match is found. Else, None.
        """
        qvars = {
            "cid": client_id
        }
        rows = self.db.select(self.table, where="client_id=$cid", vars=qvars, limit=1)
        client = rows.first()
        return client