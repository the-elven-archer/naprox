#!/usr/bin/env python2

from flask import Flask
from flask import render_template, Response, request
from functools import wraps

import json


app = Flask(__name__)


# Auth
def check_auth(username, password):
    return username == app.config['username'] and password == app.config['password']


def authenticate():
    return Response('login required',
                    401,
                    {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if app.config['username'] is not None or app.config['password'] is not None:
            auth = request.authorization
            if not auth or not check_auth(auth.username, auth.password):
                return authenticate()
        return f(*args, **kwargs)
    return decorated
#


@app.route("/")
@requires_auth
def index():
    current_servers = app.config['heartbeat'].config_nameservers
    config_servers = app.config['heartbeat'].configuration['nameservers']['default']
    last_check = app.config['heartbeat'].last_check
    return render_template("status.html",
                           current_servers=current_servers,
                           config_servers=config_servers,
                           last_check=last_check)


@app.route("/json")
@requires_auth
def json_api():
    current_servers = app.config['heartbeat'].config_nameservers
    config_servers = app.config['heartbeat'].configuration['nameservers']['default']
    return_dictionary = {"servers": []}
    for server in config_servers:
        if server in current_servers:
            return_dictionary['servers'].append({server: 'OK'})
        else:
            return_dictionary['servers'].append({server: 'FAIL'})

    return Response(json.dumps(return_dictionary,
                               indent=4,
                               sort_keys=True),
                    mimetype="application/json")
