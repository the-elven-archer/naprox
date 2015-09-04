#!/usr/bin/env python2

from flask import Flask
from flask import render_template
from flask import redirect

app = Flask(__name__)


@app.route("/")
def index():
    current_servers = app.config['heartbeat'].config_nameservers
    config_servers = app.config['heartbeat'].configuration['nameservers']['default']
    return render_template("status.html",
                           current_servers=current_servers,
                           config_servers=config_servers)
