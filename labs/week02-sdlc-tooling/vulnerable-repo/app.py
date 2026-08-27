"""
Secured Week 2 sample application.
"""

import ipaddress
import os
import sqlite3
import subprocess

from argon2 import PasswordHasher
from flask import Flask, request

app = Flask(__name__)
password_hasher = PasswordHasher()

# CWE-798 fixed: secrets are loaded from environment variables.
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
DB_PASSWORD = os.environ["DB_PASSWORD"]


@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")

    # CWE-89 fixed: parameterized SQL query.
    rows = con.execute(
        "SELECT * FROM users WHERE name = ?",
        (name,),
    ).fetchall()

    con.close()
    return str(rows)


@app.route("/ping")
def ping():
    supplied_host = request.args.get("host", "127.0.0.1")

    try:
        host = str(ipaddress.ip_address(supplied_host))
    except ValueError:
        return "Invalid IP address", 400

    # CWE-78 fixed: validated input, argument list, and no shell=True.
    return subprocess.check_output(
        ["ping", "-c", "1", host],
        text=True,
    )


def store_password(password):
    # CWE-916/CWE-327 fixed: PasswordHasher uses Argon2id.
    return password_hasher.hash(password)


if __name__ == "__main__":
    app.run(debug=False)  # CWE-489 fixed