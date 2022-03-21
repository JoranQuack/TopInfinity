from flask import Flask, render_template, g, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from PIL import Image, ImageDraw, ImageFilter
import sqlite3
import hashlib
import glob
import cv2
import os

UPLOAD_FOLDER = 'static/pfps/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
DATABASE = "users.db"

app = Flask(__name__)
app.secret_key = 'mysecretkey'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.get("/")
def home():
    if 'username' in session:
        cursor = get_db().cursor()
        sql = "SELECT username FROM users"
        cursor.execute(sql)
        results = cursor.fetchall()
        for i in range(len(results)):
            results[i] = results[i][0]
        if session['username'] in results:
            cursor = get_db().cursor()
            sql = "SELECT password FROM users"
            cursor.execute(sql)
            results = cursor.fetchall()
            for i in range(len(results)):
                results[i] = results[i][0]
            if session['password'] in results:
                cursor = get_db().cursor()
                sql = "SELECT * FROM users WHERE username = ?"
                cursor.execute(sql, (session['username'], ))
                results = cursor.fetchall()
                session['pfp'] = results[0][3]
                print(session['pfp'])
                return render_template('home.html')
            else:
                errorMessage = "Incorrect password, please try again."
                return render_template('signin.html', errorMessage=errorMessage)
        else:
            errorMessage = "Username does not exist."
            return render_template('signin.html', errorMessage=errorMessage)
    else:
        errorMessage = "You are not logged in."
        return render_template('error.html', errorMessage=errorMessage)


@app.post('/')
def home_post():
    username = request.form['username']
    password = request.form['password']
    h = hashlib.md5(password.encode())
    password = h.hexdigest()
    cursor = get_db().cursor()
    sql = "SELECT username FROM users"
    cursor.execute(sql)
    results = cursor.fetchall()
    for i in range(len(results)):
        results[i] = results[i][0]
    if username not in results:
        cursor = get_db().cursor()
        sql = "INSERT INTO users(username,password,pfp) VALUES(?,?,?)"
        cursor.execute(sql, (username, password, "/static/pfps/default.png"))
        get_db().commit()
        session['username'] = username
        session['password'] = password
        return redirect(url_for('home'))
    else:
        errorMessage = "Username is already in use, please choose something else."
        return render_template('signup.html', errorMessage=errorMessage)


@app.route("/signup")
def signup():
    return render_template('signup.html')


@app.route("/account")
def account():
    cursor = get_db().cursor()
    sql = "SELECT * FROM users"
    cursor.execute(sql)
    results = cursor.fetchall()
    return render_template('account.html', results=results)


@app.route('/pfp', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No image selected for uploading')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        session['pfp'] = f"static/pfps/{filename}"
        cursor = get_db().cursor()
        sql = "UPDATE users SET pfp = ? WHERE username = ?"
        cursor.execute(sql, (session['pfp'], session['username'], ))
        get_db().commit()
        return render_template('home.html')
    else:
        flash('Allowed image types are -> png, jpg, jpeg, gif')
        return redirect(request.url)


@app.route('/display/<filename>')
def display_image(filename):
    #print('display_image filename: ' + filename)
    return redirect(url_for('static', filename='uploads/' + filename), code=301)


@app.route("/signin", methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        session['username'] = request.form['username']
        password = request.form['password']
        h = hashlib.md5(password.encode())
        session['password'] = h.hexdigest()
        return redirect(url_for('home'))
    return render_template('signin.html')


@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
