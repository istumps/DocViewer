from flask import Flask, jsonify, request, render_template, redirect, url_for, flash
from pymongo import MongoClient
from datetime import datetime, timedelta
from functools import wraps
from bson.objectid import ObjectId
import bcrypt
import jwt


app = Flask(__name__)
app.config["SECRET_KEY"] = "DyyyzMi8As"
MAX_CONTENT_LENGTH = 5242880  # 5 MB max file size


client = MongoClient("localhost", 27017)
db = client.doc_viewer
users_collection = db.users
files_collection = db.files

#check if file is a txt file
def is_txt(filename):
    return filename.lower().endswith(".txt")


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # check cookies and headers
        token = request.cookies.get("x-access-token") or request.headers.get(
            "x-access-token"
        )
        if not token:
            return jsonify({"message": "Token is missing!"}), 403
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = users_collection.find_one({"username": data["user"]})
            if not current_user:
                return jsonify({"message": "User not found!"}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token is invalid!"}), 403

        return f(current_user, *args, **kwargs)

    return decorated

#home page
@app.route("/")
def home():
    return render_template("login.html")

#signup page
@app.route("/signup", methods=["POST"])
def signup():
    data = request.form
    username = data.get("new_username")
    password = data.get("new_password")
    confirm_password = data.get("confirm_password")

    if not username or not password or password != confirm_password:
        return (
            jsonify(
                {"message": "Missing username or password or Passwords do not match"}
            ),
            400,
        )

    if users_collection.find_one({"username": username}):
        return jsonify({"message": "username taken"}), 400

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    users_collection.insert_one({"username": username, "password": hashed_password})
    token = jwt.encode(
        {"user": username, "exp": datetime.utcnow() + timedelta(hours=1)},
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )
    response = redirect(url_for("auth"))
    response.set_cookie("x-access-token", token)

    return response

#login page
@app.route("/login", methods=["POST"])
def login():
    data = request.form
    username = data.get("username")
    password = data.get("password")

    user = users_collection.find_one({"username": username})
    if user and bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        token = jwt.encode(
            {"user": username, "exp": datetime.utcnow() + timedelta(hours=1)},
            app.config["SECRET_KEY"],
            algorithm="HS256",
        )

        response = jsonify({"message": "login successful"})
        response.set_cookie("x-access-token", token)

        response.headers["Location"] = "/auth"
        return response, 302

    return jsonify({"message": "invalid"}), 401

#dashboard page
@app.route("/auth", methods=["GET"])
@token_required
def auth(current_user):
    username = current_user["username"]
    user_files = list(files_collection.find({"owner": username}))

    for file in user_files:
        file["_id"] = str(file["_id"])

    return render_template("dashboard.html", user=current_user, files=user_files)

#upload file route
@app.route("/upload", methods=["POST"])
@token_required
def upload(current_user):
    username = current_user["username"]
    file = request.files["file"]

    if not is_txt(file.filename):
        return redirect(url_for("auth", error="Only .txt files are allowed"))

    file_content = file.read()

    # Check size
    if len(file_content) > 5242880:
        return redirect(
            url_for(
                "auth",
                error=f"File size exceeds maximum limit of 5 MB",
            )
        )

    files_collection.insert_one(
        {
            "filename": file.filename,
            "owner": username,
            "upload_date": datetime.now(),
            "size": len(file_content),
            "content": file_content.decode("utf-8"),
        }
    )

    return redirect(url_for("auth"))

#delete file route
@app.route("/delete/<file_id>", methods=["GET"])
@token_required
def delete_file(current_user, file_id):

    files_collection.delete_one({"_id":  ObjectId(file_id), "owner": current_user["username"]})

    return redirect(url_for("auth"))

#read file route
@app.route("/read/<file_id>")
@token_required
def read_file(current_user, file_id):

    file_doc = files_collection.find_one({"_id": ObjectId(file_id), "owner": current_user["username"]})

    if not file_doc:
        return jsonify({"message": "File not found"}), 404

    return render_template(
        "view_file.html", file=file_doc, content=file_doc["content"], user=current_user
    )

#update file route
@app.route("/update/<file_id>", methods=["POST"])
@token_required
def update_file(current_user, file_id):
    content = request.form.get("content")

    # Update file
    files_collection.update_one(
        {"_id": ObjectId(file_id), "owner": current_user["username"]},
        {
            "$set": {
                "content": content,
                "size": len(content),
                "upload_date": datetime.now(),
            }
        },
    )

    return redirect(url_for("read_file", file_id=file_id))

#public page
@app.route("/public")
def public():
    count = files_collection.count_documents({})
    files_name = files_collection.find({}, {"filename": 1, "_id": 0})
    return render_template("public.html", files=files_name,count=count)

#logout route
@app.route("/logout")
def logout():
    response = redirect(url_for("home"))
    response.delete_cookie("x-access-token")
    return response


if __name__ == "__main__":
    app.run(debug=True)
