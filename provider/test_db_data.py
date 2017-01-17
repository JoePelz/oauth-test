import dbsetup
from models.users import Users
from models.applications import Applications
from models.subscriptions import Subscriptions

db = dbsetup.get_db()

users = Users(db)
apps = Applications(db)
subs = Subscriptions(db)

try:
    boss_id = users.add("owner@company.com", "bosspass", name="Pointy Haired Boss")
except KeyError:
    boss = users.get("owner@company.com", "bosspass")
    boss_id = boss.id
try:
    user_id = users.add("user@customer.com", "secretpass", name="Bob the Customer")
except KeyError:
    user = users.get('user@customer.com', 'secretpass')
    user_id = user.id


app_id = apps.add(
    name="WidgetBuilder",
    owner_id=boss_id,
    scopes=["basic", "admin"],
    redirect_uris=["https://app.local:8080/public", "https://app.local:8080/private"])

subs.add(app_id=app_id,
         user_id=user_id,
         subscription_type="Basic Package")

