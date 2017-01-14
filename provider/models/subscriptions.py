class Subscriptions(object):
    def __init__(self, db):
        self.db = db
        self.table = "Subscriptions"

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

