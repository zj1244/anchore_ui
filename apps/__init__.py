import os

from flask import Flask

from flask_wtf.csrf import CSRFProtect
from config import *
from lib.mongo import MongoDB
from lib.log_handle import Log

from datetime import timedelta
from flask_apscheduler import APScheduler

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(64)
app.config.from_object(Config)
app.permanent_session_lifetime = timedelta(hours=6)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.jinja_env.auto_reload = True
app.config['TEMPLATES_AUTO_RELOAD'] = True

csrf = CSRFProtect()
csrf.init_app(app)

apscheduler = APScheduler()

mongo = MongoDB(host=MONGO_IP, port=MONGO_PORT, username=MONGO_USER, password=MONGO_PWD)
log = Log()
