"""
Tiny sample web app for Week 1 threat modeling.
"""

import os
import sqlite3
import uuid

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

DB = "notes.db"
UPLOAD_DIR = "uploads"
ALLOWED_EXTENSIONS = {"txt", "png", "pdf"}

os.makedirs(UPLOAD_DIR, exist_ok=True)


def init_db():
    con = sqlite3.connect(DB)
    con.execute(
        "CREATE TABLE IF NOT EXISTS notes "
        "(id INTEGER PRIMARY KEY, owner TEXT, body TEXT)"
    )
    con.commit()
    con.close()


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.route("/notes", methods=["GET", "POST"])
def notes():
    con = sqlite3.connect(DB)

    if request.method == "POST":
        owner = request.json.get("owner", "anon")
        body = request.json.get("body", "")
        con.execute(
            "INSERT INTO notes (owner, body) VALUES (?, ?)",
            (owner, body),
        )
        con.commit()

    rows = con.execute("SELECT id, owner, body FROM notes").fetchall()
    con.close()
    return jsonify(rows)


@app.route("/upload", methods=["POST"])
def upload():
    uploaded_file = request.files.get("file")

    if uploaded_file is None or not uploaded_file.filename:
        return {"error": "File is required"}, 400

    original_name = uploaded_file.filename
    sanitized_name = secure_filename(original_name)

    # Reject traversal, directory components, and unsupported extensions.
    if sanitized_name != original_name or not allowed_file(sanitized_name):
        return {"error": "Invalid filename or file type"}, 400

    # The stored path contains only a server-generated identifier.
    stored_name = uuid.uuid4().hex
    uploaded_file.save(os.path.join(UPLOAD_DIR, stored_name))

    return {"saved": stored_name}, 201


@app.route("/files/<name>")
def files(name):
    return send_from_directory(UPLOAD_DIR, name)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)