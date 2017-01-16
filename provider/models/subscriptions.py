class Subscriptions(object):
    def __init__(self, db):
        self.db = db
        self.table = "Subscriptions"

    def get_by_user(self, user_id):
        qvars = {
            'uid': user_id
        }
        query = """SELECT `S`.app_id, user_id, subscription_id, subscription_type, nicename
        FROM Subscriptions `S` JOIN Applications `A`
            ON `S`.app_id = `A`.app_id
        WHERE `S`.user_id = $uid OR `A`.owner_id = $uid"""
        rows = self.db.query(query, vars=qvars)
        return list(rows)

    def get(self, app_id, user_id):
        qvars = {
            'aid': app_id,
            'uid': user_id
        }
        rows = self.db.select(self.table, where="app_id=$aid and user_id=$uid", vars=qvars)
        return rows.first()

    def add(self, app_id, user_id, subscription_type):
        exists = self.get(app_id, user_id)
        if exists:
            raise KeyError("User already has a subscription to this application.")

        self.db.insert(self.table,
                       app_id=app_id,
                       user_id=user_id,
                       subscription_type=subscription_type)

