class Applications(object):
    def __init__(self, db):
        self.db = db
        self.table = "Applications"

    def exists(self, application_id):
        qvars = {
            "aid": application_id
        }
        rows = self.db.select(self.table, what="1", where="app_id=$aid", vars=qvars, limit=1)
        app = rows.first()
        return app is not None

    def get(self, application_id):
        """
        :param application_id: unique id to search for
        :return: All user details of a client, if a match is found. Else, None.
        """
        qvars = {
            "aid": application_id
        }
        rows = self.db.select(self.table, where="app_id=$aid", vars=qvars, limit=1)
        app = rows.first()
        return app