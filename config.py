import os

app_dir = os.path.abspath(os.path.dirname(__file__))

class BaseConfig:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'abc123efg456'


class DevelopementConfig(BaseConfig):
    DEBUG = True
    MONGODB_DATABASE_URI = os.environ.get('DEVELOPMENT_DATABASE_URI') or \
        'mongodb://localhost:27017/'


class TestingConfig(BaseConfig):
    DEBUG = True
    MONGODB_DATABASE_URI = os.environ.get('TESTING_DATABASE_URI') or \
			      'mongodb://localhost:27017/'


class ProductionConfig(BaseConfig):
    DEBUG = False
    MONGODB_DATABASE_URI = os.environ.get('PRODUCTION_DATABASE_URI') or \
	'mongodb://localhost:27017/'