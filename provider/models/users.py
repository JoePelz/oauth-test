class Users(object):
    def __init__(self, db):
        self.db = db
        self.table = "Users"

    def get(self, email, password):
        """
        :param email: The user email to search for
        :param password: The use password that corresponds to the email above
        :return: All user details if a match is found, else None.
        """
        qvars = {
            "email": email,
            "password": password
        }
        rows = self.db.select(self.table, where="email=$email and password=$password", vars=qvars, limit=1)
        user = rows.first()
        return user