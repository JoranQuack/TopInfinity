from flask import Flask, render_template, g, request, redirect, url_for
import sqlite3

DATABASE = "users.db"

app = Flask(__name__)


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


@app.route("/")
def home():
    return render_template('home.html')


@app.post('/')
def home_post():
    global username
    username = request.form['username']
    password = request.form['password']
    cursor = get_db().cursor()
    sql = "INSERT INTO users(username,password) VALUES(?,?)"
    cursor.execute(sql, (username, password))
    get_db().commit()
    return redirect(url_for('home'))


@app.route("/signup")
def signup():
    cursor = get_db().cursor()
    sql = "SELECT * FROM users"
    cursor.execute(sql)
    results = cursor.fetchall()
    return render_template('signup.html', results=results)


@app.route("/account")
def account():
    cursor = get_db().cursor()
    sql = "SELECT * FROM users WHERE username = " + username
    cursor.execute(sql)
    results = cursor.fetchall()
    return render_template('signup.html', results=results)


@app.route("/signin")
def signin():
    cursor = get_db().cursor()
    sql = "SELECT * FROM users"
    cursor.execute(sql)
    results = cursor.fetchall()
    return render_template('signin.html', results=results)


if __name__ == "__main__":
    app.run(debug=True)
