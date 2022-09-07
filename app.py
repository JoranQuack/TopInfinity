# --------------------------------------------- SETTING UP --------------------------------------------- #

# IMPORTS
from flask import Flask, render_template, g, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
import sqlite3
import hashlib
import os
import re


# SETTING CONSTANTS FOR UPLOADS AND DATABASE NAME
UPLOAD_FOLDER = 'static/pfps/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
DATABASE = "topinfinity.db"


# CONFIGURING UPLOADS, SECRET KEY, FLASK APP, AND REGEX
regex = '(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)'
app = Flask(__name__, template_folder="templates")
app.secret_key = 'mysecretkey'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.jpeg', '.jpg', '.png', '.gif', 'JPG']


# ------------------------------------------- BASIC FUNCTIONS ------------------------------------------- #

# ALLOWED FILENAMES CONFIG
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# CONNECTING TO DATABASE
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


# DATABASE CLOSE CONNECTION
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# STRIPS RESULTS FROM SQL INTO SIMPLE LISTS
def list_items(results):
    for i in range(len(results)):
        results[i] = results[i][0]
    return results


# FIND ERRORS IN USER INPUTS THAT ONLY REQUIRE LETTERS
def letter_check(check):
    error = "none"
    if check.replace(' ', '').isalpha() == False:
        error = "Your input must only include letters"
    return error


# FIND ERRORS IN USER INPUTS THAT ARE TOO LONG
def character_limit(check, number):
    error = "none"
    if len(check) > number:
        error = f"Character limit is {number}"
    return error


# CHECK FOR EMPTY INPUTS
def empty(input, type):
    error = "none"
    if input.strip() == "":
        error = f"Please enter a{type}"
    return error


# AVERAGE ALL ITEMS' RATINGS
def average_items():
    # average and then sync the ratings of each item with the user_ratings
    cursor = get_db().cursor()
    sql = "SELECT id FROM items"
    cursor.execute(sql)
    allitems = cursor.fetchall()
    list_items(allitems)
    for number in allitems:
        cursor = get_db().cursor()
        sql = "SELECT rating FROM user_ratings WHERE itemid = ?"
        cursor.execute(sql, (number, ))
        allratings = cursor.fetchall()
        list_items(allratings)
        if len(allratings) > 2:
            ratingavg = sum(allratings) / len(allratings)
        else:
            ratingavg = 0
        cursor = get_db().cursor()
        sql = "UPDATE items SET rating = ? WHERE id = ?"
        cursor.execute(sql, (ratingavg, number))
        get_db().commit()


# UPDATE THE POPULARITY OF EACH TOPIC (based off how many ratings it has overall)
def popularity_topics():
    cursor = get_db().cursor()
    sql = "SELECT id FROM topics"
    cursor.execute(sql)
    topicids = cursor.fetchall()
    list_items(topicids)
    for topicid in topicids:
        popularity = 0
        cursor = get_db().cursor()
        sql = "SELECT id FROM items WHERE topicid = ?"
        cursor.execute(sql, (topicid, ))
        itemids = cursor.fetchall()
        list_items(itemids)
        for itemid in itemids:
            cursor = get_db().cursor()
            sql = "SELECT id FROM user_ratings WHERE itemid = ?"
            cursor.execute(sql, (itemid, ))
            user_ratings = cursor.fetchall()
            list_items(user_ratings)
            popularity += len(user_ratings)
        cursor = get_db().cursor()
        sql = "UPDATE topics SET popularity = ? WHERE id = ?"
        cursor.execute(sql, (popularity, topicid))
        get_db().commit()


# --------------------------------------------- APP ROUTING --------------------------------------------- #

# DELETE ANY ACCOUNT
@app.route("/delete_account/<int:userid>")
def delete_account(userid):
    if session['adminmode'] != True:
        userid = session['userid']
    cursor = get_db().cursor()
    sql = "DELETE FROM users WHERE id=?"
    cursor.execute(sql, (userid, ))
    get_db().commit()
    # delete all ratings and topics that the user has previously made
    cursor = get_db().cursor()
    sql = "DELETE FROM user_ratings WHERE userid=?"
    cursor.execute(sql, (userid, ))
    get_db().commit()
    cursor = get_db().cursor()
    sql = "SELECT id FROM topics WHERE userid = ?"
    cursor.execute(sql, (userid,))
    topics = cursor.fetchall()
    list_items(topics)
    for topicid in topics:
        delete_topic(topicid)
    # redirect to admin page if adminmode is enabled
    if session['adminmode'] == True:
        return redirect(url_for('admin'))
    session.clear()
    return redirect(url_for('checkcreds'))


# DELETE ANY TOPIC
@app.route("/delete_topic/<int:topicid>")
def delete_topic(topicid):
    if session['adminmode'] != True:
        cursor = get_db().cursor()
        sql = "SELECT userid FROM topics WHERE id = ?"
        cursor.execute(sql, (topicid,))
        userid = cursor.fetchall()
        if userid[0][0] != session['userid']:
            return redirect(url_for('checkcreds'))
    cursor = get_db().cursor()
    sql = "DELETE FROM topics WHERE id=?"
    cursor.execute(sql, (topicid, ))
    get_db().commit()
    # delete all items inside the topic
    cursor = get_db().cursor()
    sql = "SELECT id FROM items WHERE topicid = ?"
    cursor.execute(sql, (topicid,))
    items = cursor.fetchall()
    list_items(items)
    for itemid in items:
        delete_item(itemid)
    if session['adminmode'] == True:
        return redirect(url_for('admin'))
    return redirect(url_for('checkcreds'))


# DELETE ANY ITEM
@app.route("/delete_item/<int:itemid>")
def delete_item(itemid):
    if session['adminmode'] != True:
        cursor = get_db().cursor()
        sql = "SELECT userid, topicid FROM items WHERE id = ?"
        cursor.execute(sql, (itemid, ))
        useriditem = cursor.fetchall()
        print(useriditem)
        cursor = get_db().cursor()
        sql = "SELECT userid FROM topics WHERE id = ?"
        cursor.execute(sql, (useriditem[0][1], ))
        useridtopic = cursor.fetchall()
        print(useridtopic)
        if useriditem[0][0] != session['userid'] and useridtopic[0][0] != session['userid']:
            return redirect(url_for('checkcreds'))
    cursor = get_db().cursor()
    sql = "DELETE FROM items WHERE id=?"
    cursor.execute(sql, (itemid, ))
    get_db().commit()
    # delete all user ratings associated with the item
    cursor = get_db().cursor()
    sql = "DELETE FROM user_ratings WHERE itemid=?"
    cursor.execute(sql, (itemid, ))
    get_db().commit()
    if session['adminmode'] == True:
        return redirect(url_for('admin'))
    return redirect(url_for('topic', topicid=session['topicid']))


# HOME ROUTE
@app.route("/home")
def home():
    # default to disabling adminmode
    session['adminmode'] = False
    # default errors to false
    session['error'] = False
    # run the functions that organise the home page items to be in the most relevant order
    average_items()
    popularity_topics()
    # select topics and their top 8 items to show on the home screen
    cursor = get_db().cursor()
    sql = "SELECT topics.title, topics.description, users.username, users.pfp, topics.id FROM topics JOIN users ON topics.userid = users.id ORDER BY topics.popularity DESC"
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


# SIGNIN (ALSO USED TO MAKE SURE USER IS LOGGED IN BEFORE RETURNING TO HOME.HTML)
@app.get("/")
def checkcreds():
    error = "none"
    if 'username' not in session:
        return render_template('welcome.html')
    cursor = get_db().cursor()
    sql = "SELECT password FROM users"
    cursor.execute(sql)
    passwords = cursor.fetchall()
    list_items(passwords)
    if session['password'] not in passwords:
        error = "Incorrect password, please try again"
    cursor = get_db().cursor()
    sql = "SELECT username FROM users"
    cursor.execute(sql)
    usernames = cursor.fetchall()
    list_items(usernames)
    if session['username'] not in usernames:
        error = "Username does not exist"
    if error != "none":
        return render_template('signin.html', error=error)
    cursor = get_db().cursor()
    sql = "SELECT * FROM users WHERE username = ?"
    cursor.execute(sql, (session['username'], ))
    usercreds = cursor.fetchall()
    session['email'] = usercreds[0][4]
    session['pfp'] = usercreds[0][3]
    session['userid'] = usercreds[0][0]
    session['color'] = "#5630a8"
    if usercreds[0][5]:
        session['color'] = usercreds[0][5]
    return redirect(url_for('home'))


# RENDER SIGNIN PAGE AND PUT CREDS IN SESSION FOR ERROR CHECKING
@app.route("/signin", methods=['GET', 'POST'])
def signin():
    # get the form details if a form was submitted
    if request.method == 'POST':
        password = request.form['password']
        h = hashlib.md5(password.encode())
        session['password'] = h.hexdigest()
        session['username'] = request.form['username']
        error2 = empty(password, " password")
        error1 = empty(session['username'], " username")
        if error1 != "none":
            error = error1
        elif error2 != "none":
            error = error2
        else:
            return redirect(url_for('checkcreds'))
        return render_template('signin.html', error=error)
    return render_template('signin.html')


# SIGN UP FUNCTION WITH ALL ERROR CHECKING
@app.post('/signup')
def signup_post():
    # default set error to none and get the inputed creds from user
    error = "none"
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']
    # password hashing
    h = hashlib.md5(password.encode())
    password = h.hexdigest()
    # check for character limit errors and already used usernames
    error = character_limit(username, 20)
    error = character_limit(email, 30)
    cursor = get_db().cursor()
    sql = "SELECT username FROM users"
    cursor.execute(sql)
    usernames = cursor.fetchall()
    list_items(usernames)
    if username in usernames:
        error = "Username is already in use, please choose something else"
    # use regex to validate email
    cursor = get_db().cursor()
    sql = "SELECT email FROM users"
    cursor.execute(sql)
    emails = cursor.fetchall()
    list_items(emails)
    if (re.search(regex, email)):
        if email in emails:
            error = "Email is already in use"
    else:
        error = "Email is invalid"
    error2 = empty(email, "n email")
    error3 = empty(password, " password")
    error1 = empty(username, " username")
    if error1 != "none":
        error = error1
    elif error2 != "none":
        error = error2
    elif error3 != "none":
        error = error3
    # return to signup page with error if there are any
    if error != "none":
        return render_template('signup.html', error=error, username=username, email=email, password=password)
    # insert all credentials in the database and tell user to sign in again
    cursor = get_db().cursor()
    sql = "INSERT INTO users(username, password, pfp, email, color) VALUES(?,?,?,?,?)"
    cursor.execute(sql, (username, password, "default.png", email, "#5630a8"))
    get_db().commit()
    error = "Account has been created, please sign in"
    return render_template('signin.html', error=error)


# RENDER THE SIGNUP PAGE
@app.get("/signup")
def signup():
    return render_template('signup.html')


# RENDER USER ACCOUNT PAGE
@app.route("/account")
def account():
    # select topics and their top 8 items to show on the home screen
    cursor = get_db().cursor()
    sql = "SELECT topics.title, topics.description, users.username, users.pfp, topics.id FROM topics JOIN users ON topics.userid = users.id WHERE topics.userid = ? ORDER BY topics.popularity DESC"
    cursor.execute(sql, (session['userid'], ))
    topics = cursor.fetchall()
    for i, topic in enumerate(topics):
        cursor = get_db().cursor()
        sql = "SELECT name FROM items WHERE topicid = ? ORDER BY rating DESC LIMIT 8;"
        cursor.execute(sql, (topic[4], ))
        items = cursor.fetchall()
        topic = topic + (tuple(list_items(items)), )
        topics[i] = topic
    return render_template('account.html', topics=topics, enumerate=enumerate)


# UPLOAD A NEW PROFILE PICTURE
@app.route('/pfp', methods=['POST'])
def upload_image():
    # check for ILLEGAL filetypes
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
    # set new pfp to that user
    session['pfp'] = filename
    cursor = get_db().cursor()
    sql = "UPDATE users SET pfp = ? WHERE id = ?"
    cursor.execute(sql, (session['pfp'], session['userid'], ))
    get_db().commit()
    return render_template('account.html')


# LOGOUT AND CLEAR SESSION
@app.route('/logout')
def logout():
    # remove all user creds from the session
    session.clear()
    return redirect(url_for('checkcreds'))


# DELETE ACCOUNT WITH A CONFIRMATION SCREEN AS A USER
@app.get('/userdelete_account/<confirmed>')
def userdelete_account(confirmed):
    if confirmed == "True":
        return delete_account(session['userid'])
    else:
        message = "Are you sure you would like to delete your account?"
        action = "Delete Account"
        function = "userdelete_account"
        return render_template('confirm.html', message=message, action=action, function=function)


# DELETE TOPIC WITH A CONFIRMATION SCREEN AS A USER
@app.get('/userdelete_topic/<confirmed>')
def userdelete_topic(confirmed):
    if confirmed == "True":
        return delete_topic(session['topicid'])
    else:
        message = "Are you sure you would like to delete this topic and all of its items?"
        action = "Delete Topic"
        function = "userdelete_topic"
        return render_template('confirm.html', message=message, action=action, function=function)


# DELETE AN ITEM AS A USER
@app.get('/userdelete_item/<int:itemid>')
def userdelete_item(itemid):
    return delete_item(itemid)


# ADDING A TOPIC ROUTE
@app.route('/addtopic', methods=['POST', 'GET'])
def addtopic():
    # add topic details into db and error check
    if request.method == 'POST':
        title = request.form['title'].capitalize()
        description = request.form['description']
        error = character_limit(title, 30)
        error = character_limit(description, 130)
        error = letter_check(title)
        error1 = empty(title, " title")
        error2 = empty(description, " description")
        if error1 != "none":
            error = error1
        elif error2 != "none":
            error = error2
        if error == "none":
            cursor = get_db().cursor()
            sql = "INSERT INTO topics(userid, title, description) VALUES(?,?,?)"
            cursor.execute(sql, (session['userid'], title, description))
            get_db().commit()
            cursor = get_db().cursor()
            sql = "SELECT last_insert_rowid()"
            cursor.execute(sql)
            topicid = cursor.fetchall()
            return redirect(url_for('topic', topicid=topicid[0][0]))
        else:
            return render_template('addtopic.html', error=error, title=title, description=description)
    # render the add topic page if not submitting a form
    else:
        return render_template('addtopic.html')


# EDITING EXISTING TOPIC
@app.get('/edittopic/<int:topicid>')
def edittopic(topicid):
    # get the existing topic info to prefill the form
    session['topicid'] = topicid
    cursor = get_db().cursor()
    sql = "SELECT * FROM topics WHERE id = ?"
    cursor.execute(sql, (topicid, ))
    topic = cursor.fetchall()
    if topic[0][1] == session['userid']:
        return render_template('edittopic.html', topics=topic)
    return(url_for('checkcreds'))


# ENTER EDITED TOPIC DETAILS INTO DATABASE
@app.post('/edittopic')
def edittopic_post():
    # error check and format everything
    title = request.form['title'].capitalize()
    description = request.form['description']
    error = character_limit(title, 30)
    error = character_limit(description, 130)
    error = letter_check(title)
    error1 = empty(title, " title")
    error2 = empty(description, " description")
    if error1 != "none":
        error = error1
    elif error2 != "none":
        error = error2
    # update db if no error
    if error == "none":
        cursor = get_db().cursor()
        sql = "UPDATE topics SET title = ?, description = ?  WHERE id = ?"
        cursor.execute(sql, (title, description, session['topicid']))
        get_db().commit()
        return redirect(url_for('topic', topicid=session['topicid']))
    # go back to the edit topic page if there is an error and display
    else:
        cursor = get_db().cursor()
        sql = "SELECT * FROM topics WHERE id = ?"
        cursor.execute(sql, (session['topicid'], ))
        topics = cursor.fetchall()
        return render_template('edittopic.html', topics=topics, error=error)


# SHOW TOPIC AND ALL OF ITS ITEMS
@app.get('/topic/<int:topicid>')
def topic(topicid):
    session['topicid'] = topicid
    # get all of the topic info and items (with their info)
    cursor = get_db().cursor()
    sql = "SELECT topics.title, topics.description, users.username, users.pfp, topics.userid, topics.id FROM topics JOIN users ON topics.userid = users.id WHERE topics.id = ?"
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
    # convert number ratings into star selections and add them to the end of the tuple of each item
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
    # manage errors
    return render_template('topic.html', topics=topics, items=items, enumerate=enumerate, error=session['error'])


# SUBMIT A RATING FOR A SPECIFIC ITEM
@app.post('/rate/<int:itemid>')
def rate(itemid):
    formrating = f"rating.{itemid}"
    rating = request.form[formrating]
    cursor = get_db().cursor()
    sql = "SELECT * FROM user_ratings WHERE itemid = ? AND userid = ?"
    cursor.execute(sql, (itemid, session['userid'],))
    previousrating = cursor.fetchall()
    # update rating if there is already one, create a new one if not
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


# ADD ITEM INTO A TOPIC
@app.post('/additem')
def additem():
    # format item name to look nice
    name = request.form['itemname'].capitalize()
    name = name.strip()
    error = character_limit(name, 30)
    # make sure it's not already in the database
    cursor = get_db().cursor()
    sql = "SELECT name FROM items WHERE topicid = ?"
    cursor.execute(sql, (session['topicid'],))
    previousnames = cursor.fetchall()
    list_items(previousnames)
    if name in previousnames:
        error = "Item name is already in use"
    if name.replace(' ', '').isalpha() == False:
        error = "Item name must only contain letters"
    error = empty(name, "n item name")
    if error == "none":
        cursor = get_db().cursor()
        sql = "INSERT INTO items(name, rating, userid, topicid) VALUES(?,?,?,?)"
        cursor.execute(sql, (name, 0, session['userid'], session['topicid']))
        get_db().commit()
        session['error'] = False
        return redirect(url_for('topic', topicid=session['topicid']))
    else:
        session['error'] = error
    return redirect(url_for('topic', topicid=session['topicid']))


# LET USER CHANGE THE ACCENT COLOUR OF THE WEBSITE
@app.get('/colorchange/<hex>')
def colorchange(hex):
    # change the colour of the session
    session['color'] = hex
    # store their preference with their user in db
    cursor = get_db().cursor()
    sql = "UPDATE users SET color = ? WHERE id = ?"
    cursor.execute(sql, (hex, session['userid']))
    get_db().commit()
    return redirect(url_for('account'))


# ADMIN PAGE
@app.get('/admin')
def admin():
    # redirect anyone who isn't me back to the home page
    if session['userid'] != 76:
        return redirect(url_for('checkcreds'))
    # enable adminmode for easier re routing to the same page when removing stuff
    session['adminmode'] = True
    # select all info tables (excluding user_rating because that is just a bridging table)
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


# 404 ERROR HANDLING
@app.errorhandler(404)
def error_404(error):
    return render_template('error.html', error=error), 404


# 500 ERROR HANDLING
@app.errorhandler(500)
def error_500(error):
    return render_template('error.html', error=error), 500


# ------------------------------------------ RUNNING THE APP  ------------------------------------------ #

# RUN THE APP
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
