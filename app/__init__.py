import os
from flask import Flask
from pymongo import MongoClient
from flask_login import LoginManager
from gridfs import GridFS

# создание экземпляра приложения
app = Flask(__name__)
app.config.from_object(os.environ.get('FLASK_ENV') or 'config.DevelopementConfig')

# Инициализация расширений
mongodb_client = MongoClient(app.config['MONGODB_DATABASE_URI'])
db = mongodb_client['archive']
users_collection = db['users']
pages_collection = db['pages']
access_collection = db['access']

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

grid_fs = GridFS(db)

from . import views