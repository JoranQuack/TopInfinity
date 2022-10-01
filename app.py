# --------------------------------------------- SETTING UP --------------------------------------------- #

# IMPORTS
from flask import Flask, render_template, g, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
from email.message import EmailMessage
from flask_mail import Mail
from dotenv import load_dotenv
from random import randint
from datetime import date
from pathlib import Path

import sqlite3, hashlib, os, re, smtplib, ssl


# SETTING CONSTANTS FOR UPLOADS AND DATABASE NAME
UPLOAD_FOLDER = 'static/pfps/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
DATABASE = "./topinfdb/topinfinity.db"


# CONFIGURING UPLOADS, FLASK APP, AND REGEX
regex = '(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)'
app = Flask(__name__, template_folder="templates")
mail = Mail(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.jpeg', '.jpg', '.png', '.gif', '.JPG']
allowed_ratings = ["1", "2", "3", "4", "5"]


# GET KEYS FROM HIDDEN .ENV FILE (NOT ON GITHUB)
dotenv_path = Path('secrets.env')
load_dotenv(dotenv_path=dotenv_path)
salt = os.getenv('SALT')
app.secret_key = os.getenv('SECRETKEY')
#set up emailing system
email_sender = 'noreplytopinfinity@gmail.com'
email_password = os.getenv('PASSWORD')



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


# SALT OLD UNSALTED PASSWORDS IF NOT SALTED
def hash_manager(password, username):
    salted_password = password + salt
    salted_password = hashlib.md5(salted_password.encode()).hexdigest()
    unsalted_password = hashlib.md5(password.encode()).hexdigest()
    cursor = get_db().cursor()
    sql = "SELECT password FROM users WHERE username = ?"
    cursor.execute(sql, (username, ))
    passwords = cursor.fetchall()
    list_items(passwords)
    if unsalted_password in passwords and salted_password not in passwords:
        cursor = get_db().cursor()
        sql = "UPDATE users SET password = ? WHERE username = ?"
        cursor.execute(sql, (salted_password, username))
        get_db().commit()
    password = salted_password
    return password


# SEND EMAILS
def sendemail(email_receiver, username, confirm_key):
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = f"{username}, please verify your new Top Infinity account."
    em.set_content(f"Please click this link to confirm your account: https://topinfinity.blackdahu.com/confirm/{confirm_key}")
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, em.as_string())



# --------------------------------------------- APP ROUTING --------------------------------------------- #

# DELETE ANY ACCOUNT
@app.route("/delete_account/<int:userid>")
def delete_account(userid):
    if session['adminmode'] != True:
        userid = session['userid']
    if userid != 76:
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
        cursor = get_db().cursor()
        sql = "SELECT userid FROM topics WHERE id = ?"
        cursor.execute(sql, (useriditem[0][1], ))
        useridtopic = cursor.fetchall()
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
    session['error'] = "none"
    return redirect(url_for('topic', topicid=session['topicid']))


# HOME ROUTE
@app.route("/home")
def home():
    # default to disabling adminmode
    session['adminmode'] = False
    # default errors to false
    session['error'] = False
    # default messages to false, note message if there is one
    try:
        message = session['message']
    except:
        message = "none"
    session['message'] = False
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
    return render_template('home.html', topics=topics, enumerate=enumerate, message=message)


# SIGNIN (ALSO USED TO MAKE SURE USER IS LOGGED IN BEFORE RETURNING TO HOME.HTML)
@app.get("/")
def checkcreds():
    error = "none"
    if 'username' not in session:
        return render_template('welcome.html')
    cursor = get_db().cursor()
    sql = "SELECT password FROM users WHERE username = ?"
    cursor.execute(sql, (session['username'], ))
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
    email = usercreds[0][4]
    session['userid'] = usercreds[0][0]
    session['adminmode'] = False
    color = usercreds[0][5]
    if len(color) == 17:
        return render_template('waiting.html', email=email, userid=session['userid'])
    if error == "Please sign in first": 
        return redirect(request.referrer)
    session['pfp'] = usercreds[0][3]
    session['email'] = email
    session['color'] = color
    return redirect(url_for('home'))


# RENDER SIGNIN PAGE AND PUT CREDS IN SESSION FOR ERROR CHECKING
@app.route("/signin", methods=['GET', 'POST'])
def signin():
    # get the form details if a form was submitted
    if request.method == 'POST':
        session['username'] = request.form['username']
        password = request.form['password']
        password = hash_manager(password, session['username'])
        session['password'] = password
        if empty(session['username'], " username") != "none":
            error = empty(session['username'], " username")
        elif empty(password, " password") != "none":
            error = empty(password, " password")
        else:
            return redirect(url_for('checkcreds'))
        return render_template('signin.html', error=error)
    return render_template('signin.html')


# SIGN UP FUNCTION WITH ALL ERROR CHECKING
@app.post('/signup')
def signup_post():
    # default set error to none and get the inputed creds from user
    username = request.form['username']
    password = request.form['password']
    confpassword = request.form["confpassword"]
    email = request.form['email']
    # check for character limit errors and already used usernames
    cursor = get_db().cursor()
    sql = "SELECT username FROM users"
    cursor.execute(sql)
    usernames = cursor.fetchall()
    list_items(usernames)
    # use regex to validate email
    cursor = get_db().cursor()
    sql = "SELECT email FROM users"
    cursor.execute(sql)
    emails = cursor.fetchall()
    list_items(emails)
    # error checking
    error = "none"
    if username in usernames:
        error = "Username is already in use, please choose something else"
    elif (re.search(regex, email)) == None:
        error = "Email is invalid"
    elif email in emails:
        error = "Email is already in use"
    elif character_limit(username, 20) != "none":
        error = character_limit(username, 20)
    elif character_limit(email, 30) != "none":
        error = character_limit(email, 30)
    elif empty(email, "n email") != "none":
        error = empty(email, "n email")
    elif empty(password, " password") != "none":
        error = empty(password, " password")
    elif empty(username, " username") != "none":
        error = empty(username, " username")
    elif password != confpassword:
        error = "Passwords don't match"
    # return to signup page with error if there are any
    if error != "none":
        return render_template('signup.html', error=error, username=username, email=email, password=password)
    # password hashing
    h = password + salt
    password = hashlib.md5(h.encode()).hexdigest()
    # create random key for email verification, and add the date for expiry handling
    key = randint(100000000, 999999999)
    today = date.today()
    today = int(today.strftime("%Y%m%d"))
    state = str(today) + str(key)
    cursor = get_db().cursor()
    sql = "INSERT INTO users(username, password, pfp, email, color) VALUES(?,?,?,?,?)"
    cursor.execute(sql, (username, password, "default.png", email, state))
    get_db().commit()
    # send user to the waiting html
    cursor = get_db().cursor()
    sql = "SELECT last_insert_rowid()"
    cursor.execute(sql)
    userid = cursor.fetchone()
    session['adminmode'] = False
    session['userid'] = userid[0]
    sendemail(email, username, state)
    return render_template('waiting.html', email=email, userid=userid[0])


# RENDER THE SIGNUP PAGE
@app.get("/signup")
def signup():
    return render_template('signup.html')


# CONFIRM EMAIL
@app.route("/confirm/<int:key>")
def confirm(key):
    cursor = get_db().cursor()
    sql = "SELECT * FROM users WHERE color = ?"
    cursor.execute(sql, (key, ))
    userinfo = cursor.fetchall()
    key = str(key)
    today = date.today()
    today = str(int(today.strftime("%Y%m%d")))
    keydate = key[0:8]
    print(keydate)
    print(today)
    if len(userinfo) == 0:
        title = "How'd you get here?"
        error = "The link you've gone to seems to be invalid, please sign in."
        return render_template('error.html', title=title, error=error)
    elif keydate != today:
        cursor = get_db().cursor()
        sql = "DELETE FROM users WHERE id = ?"
        cursor.execute(sql, (userinfo[0][0], ))
        get_db().commit()
        title = "You're out of time!"
        error = "That link is now expired. We've deleted your account, so sign up again to make another!"
        return render_template('error.html', title=title, error=error)
    session['userid'] = userinfo[0][0]
    session['username'] = userinfo[0][1]
    session['password'] = userinfo[0][2]
    session['pfp'] = userinfo[0][3]
    session['email'] = userinfo[0][4]
    session['color'] = "#5630a8"
    cursor = get_db().cursor()
    sql = "UPDATE users SET color = ? WHERE id = ?"
    cursor.execute(sql, (session['color'], session['userid']))
    get_db().commit()
    session['message'] = "Email has been verified"
    return redirect(url_for('checkcreds'))



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
    message = session['message']
    session['message'] = "none"
    error = session['error']
    session['error'] = "none"
    return render_template('account.html', topics=topics, enumerate=enumerate, message=message, error=error)


# UPLOAD A NEW PROFILE PICTURE
@app.route('/pfp', methods=['POST'])
def upload_image():
    # check for ILLEGAL filetypes
    if 'file' not in request.files:
        flash('No file part')
    file = request.files['file']
    filename = secure_filename(file.filename)
    if filename != '':
        # make sure to not overwite other files
        file_ext = os.path.splitext(filename)[1]
        pfps = os.listdir('static/pfps/')
        while filename in pfps:
            root = os.path.splitext(filename)[0]
            filename = root + "ya" + file_ext
        if file_ext not in app.config['UPLOAD_EXTENSIONS']:
            error = "Allowed image types are: png, jpg, jpeg, gif"
            return render_template('account.html', error=error)
        # save the file
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    # set new pfp to that user in session and db
    session['pfp'] = filename
    cursor = get_db().cursor()
    sql = "UPDATE users SET pfp = ? WHERE id = ?"
    cursor.execute(sql, (session['pfp'], session['userid'], ))
    get_db().commit()
    session['message'] = "Profile picture updated"
    return redirect(url_for('account'))


# CHANGE PASSWORDS
@app.post('/pwdupdate')
def pwdupdate():
    password = request.form['password']
    confpassword = request.form["confpassword"]
    oldpassword = request.form['oldpassword']
    # get correct old password
    cursor = get_db().cursor()
    sql = "SELECT password FROM users WHERE id = ?"
    cursor.execute(sql, (session['userid'], ))
    currentpassword = cursor.fetchone()[0]
    h = oldpassword + salt
    oldpassword = hashlib.md5(h.encode()).hexdigest()
    # error checking
    error = "none"
    if empty(password, " password") != "none":
        error = empty(password, " password")
    elif password != confpassword:
        error = "Passwords don't match"
    elif session['password'] != currentpassword:
        return redirect(url_for('checkcreds'))
    elif currentpassword != oldpassword:
        error = "Your current password is wrong"
    if error == "none":
        # password hashing
        h = password + salt
        password = hashlib.md5(h.encode()).hexdigest()
        # put in db
        cursor = get_db().cursor()
        sql = "UPDATE users SET password = ? WHERE id = ?"
        cursor.execute(sql, (password, session['userid'], ))
        get_db().commit()
        session['password'] = password
        session['message'] = "Password was changed"
    else:
        session['error'] = error
    return redirect(url_for('account'))


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
        error = "none"
        if character_limit(title, 30) != "none":
            error = character_limit(title, 30)
        elif character_limit(description, 100) != "none":
            error = character_limit(description, 100)
        elif letter_check(title) != "none":
            error = letter_check(title)
        elif empty(title, " title") != "none":
            error = empty(title, " title")
        elif empty(description, " description") != "none":
            error = empty(description, " description")
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
    else:
        return redirect(url_for('checkcreds'))


# ENTER EDITED TOPIC DETAILS INTO DATABASE
@app.post('/edittopic')
def edittopic_post():
    cursor = get_db().cursor()
    sql = "SELECT * FROM topics WHERE id = ?"
    cursor.execute(sql, (session['topicid'], ))
    topic = cursor.fetchall()
    if topic[0][1] != session['userid']:
        return redirect(url_for('checkcreds'))
    # error check and format everything
    title = request.form['title'].capitalize()
    description = request.form['description']
    error = "none"
    if character_limit(title, 30) != "none":
        error = character_limit(title, 30)
    elif character_limit(description, 100) != "none":
        error = character_limit(description, 100)
    elif letter_check(title) != "none":
        error = letter_check(title)
    elif empty(title, " title") != "none":
        error = empty(title, " title")
    elif empty(description, " description") != "none":
        error = empty(description, " description")
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
    error = session['error']
    return render_template('topic.html', topics=topics, items=items, enumerate=enumerate, error=error)


# SUBMIT A RATING FOR A SPECIFIC ITEM
@app.post('/rate/<int:itemid>')
def rate(itemid):
    formrating = f"rating.{itemid}"
    rating = request.form[formrating]
    if rating not in allowed_ratings:
        return redirect('checkcreds')
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
    session['error'] = "none"
    return redirect(url_for('topic', topicid=session['topicid']))


# ADD ITEM INTO A TOPIC
@app.post('/additem')
def additem():
    # format item name to look nice
    name = request.form['itemname'].capitalize()
    name = name.strip()
    # make sure it's not already in the database
    cursor = get_db().cursor()
    sql = "SELECT name FROM items WHERE topicid = ?"
    cursor.execute(sql, (session['topicid'],))
    previousnames = cursor.fetchall()
    list_items(previousnames)
    error = "none"
    if name in previousnames:
        error = "Item name is already in use"
    elif character_limit(name, 30) != "none":
        error = character_limit(name, 30)
    elif empty(name, "n item name") != "none":
        error = empty(name, "n item name")
    if error == "none":
        cursor = get_db().cursor()
        sql = "INSERT INTO items(name, rating, userid, topicid) VALUES(?,?,?,?)"
        cursor.execute(sql, (name, 0, session['userid'], session['topicid']))
        get_db().commit()
        session['error'] = False
        return redirect(url_for('topic', topicid=session['topicid']))
    session['error'] = error
    return redirect(url_for('topic', topicid=session['topicid']))


# LET USER CHANGE THE ACCENT COLOUR OF THE WEBSITE
@app.get('/colorchange/<hex>')
def colorchange(hex):
    if "#" not in hex:
        hex = "fun"
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


# RUN CLEAN UPS ON APP START
@app.before_first_request
def cleanup():
    # remove unused pfps
    cursor = get_db().cursor()
    sql = "SELECT pfp FROM users"
    cursor.execute(sql)
    usedpfps = cursor.fetchall()
    list_items(usedpfps)
    pfps = os.listdir('static/pfps/')
    for pfp in pfps:
        if pfp not in usedpfps:
            os.remove(f"static/pfps/{pfp}")
    # remove unconfirmed accounts from the database
    cursor = get_db().cursor()
    sql = "SELECT id, color FROM users"
    cursor.execute(sql)
    users = cursor.fetchall()
    for user in users:
        if len(user[1]) == 17:
            cursor = get_db().cursor()
            sql = "DELETE FROM users WHERE id = ?"
            cursor.execute(sql, (user[0], ))
            get_db().commit()


# ------------------------------------------- ERROR HANDLERS  ------------------------------------------- #

# 404 ERROR HANDLING
@app.errorhandler(404)
def error_404(error):
    title = "Oops! That page doesn't exist!"
    return render_template('error.html', title=title, error=error), 404


# 500 ERROR HANDLING
@app.errorhandler(500)
def error_500(error):
    title = ":( there has been an error"
    if 'username' not in session:
        error = "Please sign in first"
        return render_template('signin.html', error=error)
    return render_template('error.html', title=title, error=error), 500



# ------------------------------------------ RUNNING THE APP  ------------------------------------------ #

# RUN THE APP
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
