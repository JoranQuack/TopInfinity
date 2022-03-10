from flask import Flask, render_template, g, request, redirect, url_for, session
import sqlite3
import time
import hashlib

DATABASE = "users.db"

app = Flask(__name__)

app.secret_key = 'mysecretkey'


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
                print(results[0][3])
                return render_template('home.html', userData=results)
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
        sql = "INSERT INTO users(username,password, pfp) VALUES(?,?,?)"
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
