
class Subscriptions(object):
    def __init__(self, db):
        self.db = db
        self.table = "Subscriptions"

    def add(self, app_id, user_id, subscription_type):
        self.db.insert(self.table,
                       app_id=app_id,
                       user_id=user_id,
                       subscription_type=subscription_type)

