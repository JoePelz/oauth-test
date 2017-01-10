import web


class Users(object):
    def __init__(self, db):
        self.db = db
        self.table = "Users"

    def get(self, email, password):
        db = web.database(dbn='sqlite', db="/.")
        self.db.select()