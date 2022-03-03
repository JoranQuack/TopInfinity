from flask import Flask, render_template, g, request, redirect, url_for, session
import sqlite3
import time

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
    cursor = get_db().cursor()
    sql = "SELECT * FROM users"
    cursor.execute(sql)
    results = cursor.fetchall()
    if 'username' in session:
        if username in results:
            return render_template('home.html')
        else:
            errorMessage = "Username does not exist. Please signup."
            return render_template('error.html', errorMessage=errorMessage)
    else:
        errorMessage = "You are not logged in."
        return render_template('error.html', errorMessage=errorMessage)


@app.post('/')
def home_post():
    username = request.form['username']
    password = request.form['password']
    cursor = get_db().cursor()
    sql = "INSERT INTO users(username,password) VALUES(?,?)"
    cursor.execute(sql, (username, password))
    get_db().commit()


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
    sql = "SELECT * FROM users"
    cursor.execute(sql)
    results = cursor.fetchall()
    return render_template('account.html', results=results)


@app.route("/signin", methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        session['username'] = request.form['username']
        username = request.form['username']
        return redirect(url_for('home', username=username))
    return render_template('signin.html')


@app.route('/logout')   
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
