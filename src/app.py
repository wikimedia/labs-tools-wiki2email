#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import yaml
from flask import session, redirect, request, jsonify, render_template, url_for, \
    make_response
from flask import Flask
import requests
from flask_jsonlocale import Locales
from flask_mwoauth import MWOAuth
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import subprocess

app = Flask(__name__, static_folder='../static')

# Load configuration from YAML file
__dir__ = os.path.dirname(__file__)
app.config.update(
    yaml.safe_load(open(os.path.join(__dir__, os.environ.get(
        'FLASK_CONFIG_FILE', 'config.yaml')))))
locales = Locales(app)
_ = locales.get_message

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    token_key = db.Column(db.String(255))
    token_secret = db.Column(db.String(255))
    wikis = db.relationship('Wiki', backref='user', lazy=True)

class Wiki(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    dbname = db.Column(db.String(255))

mwoauth = MWOAuth(
    consumer_key=app.config.get('CONSUMER_KEY'),
    consumer_secret=app.config.get('CONSUMER_SECRET'),
    base_url=app.config.get('OAUTH_MWURI'),
)
app.register_blueprint(mwoauth.bp)

def logged():
    return mwoauth.get_current_user() is not None

@app.before_request
def force_https():
    if request.headers.get('X-Forwarded-Proto') == 'http':
        return redirect(
            'https://' + request.headers['Host'] + request.headers['X-Original-URI'],
            code=301
        )

def get_user():
    return User.query.filter_by(
        username=mwoauth.get_current_user()
    ).first()

@app.before_request
def db_init_user():
    if logged():
        user = get_user()
        access_token = session.get('mwoauth_access_token', {})
        request_token_secret = access_token.get('secret').decode('utf-8')
        request_token_key = access_token.get('key').decode('utf-8')
        if user is None:
            user = User(
                username=mwoauth.get_current_user(),
                token_key=request_token_key,
                token_secret=request_token_key,
            )
            db.session.add(user)
            db.session.commit()
        else:
            user.token_key = request_token_key
            user.token_secret = request_token_secret
            if not user.is_active:
                return render_template('permission_denied.html'), 403
            db.session.commit()

@app.context_processor
def inject_base_variables():
    return {
        "logged": logged(),
        "username": mwoauth.get_current_user(),
        "revision": get_revision(),
        "revision_link": get_revision_link()
    }

def get_revision():
    try:
        output = subprocess.check_output(["git", "describe", "--always"], stderr=subprocess.STDOUT).strip().decode()
        assert 'fatal' not in output
        return output
    except Exception:
        # if somehow git version retrieving command failed, just return
        return ''

def get_revision_link():
    base_link = "https://gerrit.wikimedia.org/g/labs/tools/wiki2email/"
    try:
        output = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.STDOUT).strip().decode()
        assert 'fatal' not in output
        return base_link + "+/" + output
    except Exception:
        # on fail return empty repo link
        return base_link

@app.route('/')
def index():
    if logged():
        return render_template('index.html')
    else:
        return render_template('login.html')

if __name__ == "__main__":
    app.run()