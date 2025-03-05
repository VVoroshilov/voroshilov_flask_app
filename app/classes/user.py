from app import db, login_manager, users_collection
from flask_login import UserMixin
from bson import ObjectId


@login_manager.user_loader
def load_user(user_id):
    user_obj = users_collection.find_one({'_id': ObjectId(str(user_id))})
    if user_obj:
        return User(user_obj)
    return None


class User(UserMixin):
    def __init__(self, user_obj):
        self.id = user_obj['_id']
        self.user_id = user_obj['user_id']
        self.user_name = user_obj['user_name']
        self.email = user_obj['email']
        self.account_type = user_obj['account_type']