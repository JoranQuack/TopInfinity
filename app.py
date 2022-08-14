from flask import Flask, render_template, g, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from PIL import Image, ImageDraw, ImageFilter
import sqlite3
import hashlib
import os
import re

UPLOAD_FOLDER = 'static/pfps/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
DATABASE = "topinfinity.db"

regex = '(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)'
app = Flask(__name__, template_folder="templates")
app.secret_key = 'mysecretkey'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.jpeg', '.jpg', '.png', '.gif', 'JPG']


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


def list_items(results):
    for i in range(len(results)):
        results[i] = results[i][0]
    return results


def letter_check(check):
    error = "none"
    if check.replace(' ', '').isalpha() == False:
        error = "Title must only include letters"
    return error


def character_limit(check, number):
    if len(check) > number:
        error = f"Character limit is {number}."
    else:
        error = "none"
    return error


@app.post("/delete_account/<int:userid>")
def delete_account(userid):
    cursor = get_db().cursor()
    sql = "DELETE FROM users WHERE id=?"
    cursor.execute(sql, (userid, ))
    get_db().commit()
    session.clear()
    cursor = get_db().cursor()
    sql = "DELETE FROM user_ratings WHERE userid=?"
    cursor.execute(sql, (userid, ))
    get_db().commit()
    cursor = get_db().cursor()
    sql = "SELECT id FROM topics WHERE userid = ?"
    cursor.execute(sql, (userid,))
    topics = cursor.fetchall()
    list_items(topics)
    for topic in topics:
        delete_item(topic)
    return redirect(url_for('checkcreds'))


@app.post("/delete_topic/<int:topicid>")
def delete_topic(topicid):
    cursor = get_db().cursor()
    sql = "DELETE FROM topics WHERE id=?"
    cursor.execute(sql, (topicid, ))
    get_db().commit()
    cursor = get_db().cursor()
    sql = "SELECT id FROM items WHERE topicid = ?"
    cursor.execute(sql, (topicid,))
    items = cursor.fetchall()
    list_items(items)
    for item in items:
        delete_item(item)
    return redirect(url_for('checkcreds'))


@app.post("/delete_item/<int:itemid>")
def delete_item(itemid):
    cursor = get_db().cursor()
    sql = "DELETE FROM items WHERE id=?"
    cursor.execute(sql, (itemid, ))
    get_db().commit()
    cursor = get_db().cursor()
    sql = "DELETE FROM user_ratings WHERE itemid=?"
    cursor.execute(sql, (itemid, ))
    get_db().commit()
    try:
        return redirect(url_for('topic', topicid=session['topicid']))
    except:
        return redirect(url_for('admin'))


@app.route("/home")
def home():
    cursor = get_db().cursor()
    sql = "SELECT id FROM items"
    cursor.execute(sql)
    allitems = cursor.fetchall()
    list_items(allitems)
    for number in allitems:
        cursor = get_db().cursor()
        sql = "SELECT rating FROM user_ratings WHERE itemid = ?"
        cursor.execute(sql, (number,))
        allratings = cursor.fetchall()
        list_items(allratings)
        try:
            ratingavg = sum(allratings) / len(allratings)
        except:
            ratingavg = 0
        cursor = get_db().cursor()
        sql = "UPDATE items SET rating = ? WHERE id = ?"
        cursor.execute(sql, (ratingavg, number))
        get_db().commit()
    cursor = get_db().cursor()
    sql = "SELECT topics.title, topics.description, users.username, users.pfp, topics.id FROM topics JOIN users ON topics.userid = users.id;"
    cursor.execute(sql)
    topics = cursor.fetchall()
    for i, topic in enumerate(topics):
        cursor = get_db().cursor()
        sql = "SELECT name FROM items WHERE topicid = ? ORDER BY rating DESC LIMIT 8;"
        cursor.execute(sql, (topic[4], ))
        items = cursor.fetchall()
        topic = topic + (tuple(list_items(items)), )
        topics[i] = topic
    return render_template('home.html', topics=topics, enumerate=enumerate)


@app.get("/")
def checkcreds():
    if 'username' in session:
        cursor = get_db().cursor()
        sql = "SELECT username FROM users"
        cursor.execute(sql)
        results = cursor.fetchall()
        list_items(results)
        if session['username'] in results:
            cursor = get_db().cursor()
            sql = "SELECT password FROM users"
            cursor.execute(sql)
            results = cursor.fetchall()
            list_items(results)
            if session['password'] in results:
                cursor = get_db().cursor()
                sql = "SELECT * FROM users WHERE username = ?"
                cursor.execute(sql, (session['username'], ))
                results = cursor.fetchall()
                session['email'] = results[0][4]
                session['pfp'] = results[0][3]
                session['userid'] = results[0][0]
                return redirect(url_for('home'))
            else:
                error = "Incorrect password, please try again."
                return render_template('signin.html', error=error)
        else:
            error = "Username does not exist."
            return render_template('signin.html', error=error)
    else:
        error = "To get started, please sign in."
        return render_template('welcome.html', error=error)


@app.post('/signup')
def signup_post():
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']
    h = hashlib.md5(password.encode())
    password = h.hexdigest()
    error = character_limit(username, 20)
    error = character_limit(email, 30)
    error = letter_check(username)
    cursor = get_db().cursor()
    sql = "SELECT username FROM users"
    cursor.execute(sql)
    usernames = cursor.fetchall()
    list_items(usernames)
    print(usernames)
    if username in usernames:
        error = "Username is already in use, please choose something else."
    cursor = get_db().cursor()
    sql = "SELECT email FROM users"
    cursor.execute(sql)
    emails = cursor.fetchall()
    list_items(emails)
    if (re.search(regex, email)):
        if email in emails:
            error = "Email is already in use."
    else:
        error = "Email is invalid."
    if error: 
        return render_template('signup.html', error=error)
    cursor = get_db().cursor()
    sql = "INSERT INTO users(username, password, pfp, email) VALUES(?,?,?,?)"
    cursor.execute(sql, (username, password, "default.png", email))
    get_db().commit()
    error = "Account has been created, please sign in."
    return render_template('signin.html', error=error)


@app.get("/signup")
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
    file = request.files['file']
    filename = secure_filename(file.filename)
    if filename != '':
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in app.config['UPLOAD_EXTENSIONS']:
            error = "Allowed image types are: png, jpg, jpeg, gif"
            return render_template('account.html', error=error)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    session['pfp'] = filename
    cursor = get_db().cursor()
    sql = "UPDATE users SET pfp = ? WHERE username = ?"
    cursor.execute(sql, (session['pfp'], session['username'], ))
    get_db().commit()
    return render_template('account.html')


@app.route("/signin", methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        password = request.form['password']
        h = hashlib.md5(password.encode())
        session['password'] = h.hexdigest()
        session['username'] = request.form['username']
        return redirect(url_for('checkcreds'))
    return render_template('signin.html')


@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.clear()
    return redirect(url_for('checkcreds'))


@app.get('/userdelete_account/<confirmed>')
def userdelete_account(confirmed):
    if confirmed == "True":
        return delete_account(session['userid'])
    else:
        message = "Are you sure you would like to delete your account?"
        action = "Delete Account"
        function = "userdelete_account"
        return render_template('confirm.html', message=message, action=action, function=function)


@app.get('/userdelete_topic/<confirmed>')
def userdelete_topic(confirmed):
    if confirmed == "True":
        return delete_topic(session['topicid'])
    else:
        message = "Are you sure you would like to delete this topic and all of its items?"
        action = "Delete Topic"
        function = "userdelete_topic"
        return render_template('confirm.html', message=message, action=action, function=function)


@app.get('/userdelete_item/<int:itemid>')
def userdelete_item(itemid):
    return delete_item(itemid)


@app.get('/addtopic')
def addtopic():
    return render_template('addtopic.html')


@app.post('/addtopic')
def addtopic_post():
    title = request.form['title'].capitalize()
    description = request.form['description']
    error = character_limit(title, 30)
    error = character_limit(description, 130)
    error = letter_check(title)
    if error == "none":
        cursor = get_db().cursor()
        sql = "INSERT INTO topics(userid, title, description) VALUES(?,?,?)"
        cursor.execute(sql, (session['userid'], title, description))
        get_db().commit()
        return redirect(url_for('home'))
    else:
        return render_template('addtopic.html', error=error)


@app.get('/edittopic/<int:topicid>')
def edittopic(topicid):
    session['topicid'] = topicid
    cursor = get_db().cursor()
    sql = "SELECT * FROM topics WHERE id = ?"
    cursor.execute(sql, (topicid, ))
    results = cursor.fetchall()
    return render_template('edittopic.html', topics=results)


@app.post('/edittopic')
def edittopic_post():
    title = request.form['title'].capitalize()
    description = request.form['description']
    error = character_limit(title, 30)
    error = character_limit(description, 130)
    error = letter_check(title)
    if error == "none":
        cursor = get_db().cursor()
        sql = "UPDATE topics SET title = ?, description = ?  WHERE id = ?"
        cursor.execute(sql, (title, description, session['topicid']))
        get_db().commit()
        return redirect(url_for('home'))
    else:
        cursor = get_db().cursor()
        sql = "SELECT * FROM topics WHERE id = ?"
        cursor.execute(sql, (session['topicid'], ))
        results = cursor.fetchall()
        return render_template('edittopic.html', topics=results, error=error)


@app.get('/topic/<int:topicid>')
def topic(topicid):
    session['topicid'] = topicid
    cursor = get_db().cursor()
    sql = "SELECT topics.title, topics.description, users.username, users.pfp, topics.userid FROM topics JOIN users ON topics.userid = users.id WHERE topics.id = ?"
    cursor.execute(sql, (topicid, ))
    topics = cursor.fetchall()
    cursor = get_db().cursor()
    sql = "SELECT id, name, rating, userid FROM items WHERE topicid = ? ORDER BY rating DESC"
    cursor.execute(sql, (topicid, ))
    items = cursor.fetchall()
    cursor = get_db().cursor()
    sql = "SELECT rating, itemid FROM user_ratings WHERE userid = ?"
    cursor.execute(sql, (session['userid'], ))
    user_ratings = cursor.fetchall()
    checked_numbers = {5: (0, 0, 0, 0, "checked"), 4: (0, 0, 0, "checked", 0), 3: (
        0, 0, "checked", 0, 0), 2: (0, "checked", 0, 0, 0), 1: ("checked", 0, 0, 0, 0), 0: (0, 0, 0, 0, 0)}
    for i, item in enumerate(items):
        for rating in user_ratings:
            if rating[1] == item[0]:
                item = item + (checked_numbers[rating[0]], )
        item = list(item)
        item[2] = checked_numbers[round(item[2])]
        item = tuple(item)
        if len(item) == 4:
            item = item + (checked_numbers[0], )
        items[i] = item
    return render_template('topic.html', topics=topics, items=items, enumerate=enumerate, userid=session['userid'])


@app.post('/rate/<int:itemid>')
def rate(itemid):
    formrating = f"rating.{itemid}"
    rating = request.form[formrating]
    cursor = get_db().cursor()
    sql = "SELECT * FROM user_ratings WHERE itemid = ? AND userid = ?"
    cursor.execute(sql, (itemid, session['userid'],))
    previousrating = cursor.fetchall()
    if len(previousrating) == 0:
        cursor = get_db().cursor()
        sql = "INSERT INTO user_ratings(itemid, userid, rating) VALUES(?,?,?)"
        cursor.execute(sql, (itemid, session['userid'], rating))
        get_db().commit()
    else:
        cursor = get_db().cursor()
        sql = "UPDATE user_ratings SET rating = ? WHERE userid = ? AND itemid = ?"
        cursor.execute(sql, (rating, session['userid'], itemid))
        get_db().commit()
    return redirect(url_for('topic', topicid=session['topicid']))


@app.post('/additem')
def additem():
    name = request.form['itemname'].capitalize()
    name = name.strip()
    error = character_limit(name, 50)
    cursor = get_db().cursor()
    sql = "SELECT name FROM items WHERE topicid = ?"
    cursor.execute(sql, (session['topicid'],))
    previousnames = cursor.fetchall()
    list_items(previousnames)
    if name not in previousnames and name.replace(' ', '').isalpha() == True and error == "none":
        cursor = get_db().cursor()
        sql = "INSERT INTO items(name, rating, userid, topicid) VALUES(?,?,?,?)"
        cursor.execute(sql, (name, 0, session['userid'], session['topicid']))
        get_db().commit()
    return redirect(url_for('topic', topicid=session['topicid']))


@app.get('/admin')
def admin():
    if session['userid'] != 76:
        return redirect(url_for('checkcreds'))
    cursor = get_db().cursor()
    sql = "SELECT * FROM users"
    cursor.execute(sql)
    users = cursor.fetchall()
    cursor = get_db().cursor()
    sql = "SELECT * FROM topics"
    cursor.execute(sql)
    topics = cursor.fetchall()
    cursor = get_db().cursor()
    sql = "SELECT * FROM items"
    cursor.execute(sql)
    items = cursor.fetchall()
    return render_template('admin.html', users=users, topics=topics, items=items)


if __name__ == "__main__":
    app.run(debug=True)
