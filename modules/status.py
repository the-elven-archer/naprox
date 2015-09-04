#!/usr/bin/env python2

from flask import Flask
from flask import render_template, Response

import json


app = Flask(__name__)


@app.route("/")
def index():
    current_servers = app.config['heartbeat'].config_nameservers
    config_servers = app.config['heartbeat'].configuration['nameservers']['default']
    last_check = app.config['heartbeat'].last_check
    return render_template("status.html",
                           current_servers=current_servers,
                           config_servers=config_servers,
                           last_check=last_check)


@app.route("/json")
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
