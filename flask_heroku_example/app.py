import os
import psycopg2
from flask import Flask, render_template, g, Blueprint, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
import geocoder
import googlemaps
from geopy.geocoders import Nominatim
import smtplib
from socket import gaierror
from twilio.rest import Client
bp = Blueprint('auth', __name__, url_prefix='/auth')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'XYZ')


def connect_db():
    return psycopg2.connect(os.environ.get('DATABASE_URL'))

def login_required(view):
    """View decorator that redirects anonymous users to the login page."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.cuser is None:
            return redirect(url_for('login'))

        return view(**kwargs)

    return wrapped_view
@app.before_request
def before_request():
    g.db_conn = connect_db()
    user_id = session.get('user_id')
    if user_id is None:
        g.cuser = None
    if user_id is not None:
        cur = g.db_conn.cursor()
        postgreSQL_select_Queries = "select * from cuser where id = %s"

        cur.execute(postgreSQL_select_Queries, (user_id,))
        g.cuser = cur.fetchone()
@app.route('/')
def index():
    cur = g.db_conn.cursor()
    curs = g.db_conn.cursor()
    cur.execute("SELECT * FROM authors;")
    curs.execute("SELECT * FROM book;")
    curss = g.db_conn.cursor()
    curss.execute("SELECT * FROM cuser;")
    return render_template('index.html', countries=cur.fetchall(), messages=curs.fetchall(), users=curss.fetchall())
@app.route('/googlea8820096d786119b.html')
def google():
    return render_template('blog/googlea8820096d786119b.html')
@app.route('/testImage')
def testI():
    return render_template('testImage.html')
@app.route('/browse', methods=('GET', 'POST'))
def browse():
    cur = g.db_conn.cursor()
    curs = g.db_conn.cursor()
    cur.execute("SELECT * FROM authors;")
    curs.execute("SELECT * FROM book;")
    curss = g.db_conn.cursor()
    curss.execute("SELECT * FROM cuser;")
    mess = ""
    if request.method == 'POST':
        sr = ""
        search = request.form['searches']
        mess = search
    return render_template('browse.html', countries=cur.fetchall(), messages=mess, users=curss.fetchall())
@app.route('/tailored', methods=('GET', 'POST'))
def tailored():
    cur = g.db_conn.cursor()
    curs = g.db_conn.cursor()
    cur.execute("SELECT * FROM authors;")
    curs.execute("SELECT * FROM book;")
    curss = g.db_conn.cursor()
    curss.execute("SELECT * FROM cuser;")
    return render_template('tailored.html', countries=cur.fetchall(), users=curss.fetchall())
@app.route('/login', methods=('GET', 'POST'))
def login():
    """Log in a registered user by adding the user id to the session."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cur = g.db_conn.cursor()
        error = None
        if username:
            postgreSQL_select_Query = "select * from cuser where username = %s"

            cur.execute(postgreSQL_select_Query, (username,))
            user = cur.fetchone()
            if user is None:
                error = "Incorrect username."
            elif not check_password_hash(user[1], password):
                error = "Incorrect password."
             
            if error is None:
                # store the user id in a new session and return to the index
                session.clear()
                session['user_id'] = user[5]
                return redirect(url_for('dashboard', username=user[0]))

        flash(error)

    return render_template('auth/login.html')
@app.route('/create', methods=('GET', 'POST'))
def create():
    """Create a new post for the current user."""
    cur = g.db_conn.cursor()
    curs = g.db_conn.cursor()
    theCure = g.db_conn.cursor()
    curi = g.db_conn.cursor()
    curs.execute("SELECT focus FROM cuser;")
    curi.execute("SELECT * FROM cuser;")
    focuses=curs.fetchall()
    useri = ""
    mess = ""
    mess2 = ""
    mess3 = ""
    if request.method == 'POST':
        title = request.form['titles']
        body = request.form['bodys']
        github = request.form['githubs']
        spot = request.form['demos']
        skills = request.form['skillss']
        comp = request.form['comps']
        tried = request.form['trys']
        pic = request.form['pic']
        mess=skills
        mess2=body
        mess3=comp
        useri=mess
        users=curi.fetchall()
        body2 = "Projec - user " + g.cuser[0] + " is having an issue: " + title + ", that you can help with! Check your tailored page: https://projectware.herokuapp.com/tailored"
        for u in users: 
            if useri != "":
                if u[2].lower() in useri.lower():
                    if u[2] != "":
                        if u[3] != None:
                            if u[4] != None:
                                
                                account_sid3 = 'AC226ea738b271b118c82e6843b8e48427'
                                auth_token3 = '285b6c63aeb095e084fee9c3f030202d'
                                client3 = Client(account_sid3, auth_token3)
                                
                                message3 = client3.messages \
                                    .create(
                                         body=body2,
                                         from_='+14378002075',
                                         to='+14163126190'
                                     )

                                print(message3.sid)  
                elif u[2].lower() in mess3.lower():
                    if u[2] != "":
                        if u[3] != None:
                            if u[4] != None:
                                account_sid4t = 'AC226ea738b271b118c82e6843b8e48427'
                                auth_token4t = '285b6c63aeb095e084fee9c3f030202d'
                                client4t = Client(account_sid4t, auth_token4t)

                                message4t = client4t.messages \
                                    .create(
                                         body=body2,
                                         from_='+14378002075',
                                         to='+14163126190'
                                     )

                                print(message4t.sid)        
                elif u[2].lower() in mess2.lower():
                    if u[2] != "":
                        if u[3] != None:
                            if u[4] != None:
                                account_sid4 = 'AC226ea738b271b118c82e6843b8e48427'
                                auth_token4 = '285b6c63aeb095e084fee9c3f030202d'
                                client4 = Client(account_sid4, auth_token4)

                                message4 = client4.messages \
                                    .create(
                                         body=body2,
                                         from_='+14378002075',
                                         to='+16476857747'
                                     )

                                print(message4.sid)         
        # zipped = request.form['zip']
        # files = os.path.abspath(zipped)
        # api = ipfsapi.connect('127.0.0.1', 5001)
        # file = api.add(files)
        # print(file['Hash'])
        error = None

        if not title:
            error = 'Title is required.'

        if error is not None:
            flash(error)
        else:
            stri = spot + " " + github
            cur.execute("INSERT INTO authors VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",(g.cuser[5], g.cuser[0], title, stri, body, skills, comp, tried, pic))
            g.db_conn.commit()
            # db.execute('INSERT INTO post (message) VALUES (?) WHERE id = ?', ("dick",))

    return render_template('blog/create.html', focuses=focuses, useri=mess, users=curi.fetchall(), useri2=mess2, useri3=mess3)

@app.route("/<title>/view", methods=("GET", "POST"))
def view(title):
    geolocator = Nominatim(user_agent="ruavcollab")
    """Update a post if the current user is the author."""
    cur = g.db_conn.cursor()
    curs = g.db_conn.cursor()
    a = str
    b = str
    data = {} 
    postgreSQL_select_Query = "select * from authors where title = %s"
    cur.execute(postgreSQL_select_Query, (title,))
    post = cur.fetchone()
    coordinates = post[3].split(" ")
    postgreSQL_select_Query2 = "select * from cuser where username = %s"
    curs.execute(postgreSQL_select_Query2, (post[1],))
    user = curs.fetchone()
    # location = geolocator.reverse(strin)
    spot = post[3]
    return render_template("blog/view.html", post=post, area=spot, user=user)
@app.route("/<title>/delete", methods=("GET", "POST"))
def delete(title):
    cur = g.db_conn.cursor()
    postgreSQL_delete_Query = "delete from authors where title = %s"
    cur.execute(postgreSQL_delete_Query, (title,))
    g.db_conn.commit()
    return redirect(url_for('dashboard', username=g.cuser[0]))
@app.route("/<int:id>/deleteMessage", methods=("GET", "POST"))
def deleteMessage(id):
    cur = g.db_conn.cursor()
    postgreSQL_delete_Query = "delete from book where id = %s"
    cur.execute(postgreSQL_delete_Query, (id,))
    g.db_conn.commit()
    return redirect(url_for('dashboard', username=g.cuser[0]))
@app.route("/<username>/dashboard", methods=("GET", "POST"))
def dashboard(username):
    """Update a post if the current user is the author."""

    curse = g.db_conn.cursor()
    curs = g.db_conn.cursor()
    curse.execute("SELECT * FROM authors;")
    curs.execute("SELECT * FROM book;")
    cur = g.db_conn.cursor()
    theCure = g.db_conn.cursor()
    if request.method == 'POST':
        passw = request.form['password1']
        password = request.form['password2']
        focus = request.form['focus']
        email = request.form['email']
        city = request.form['city']
        mesgeSample = ""
        nmeSample = ""
        error = None


        if error is None:
            postgreSQL_select_Query = "select * from cuser where username = %s"
            postgreSQL_update_Query2 = "update cuser set password = %s where id = %s"
            postgreSQL_update_Query3 = "update cuser set focus = %s where id = %s"
            postgreSQL_update_Query4 = "update cuser set email = %s where id = %s"
            postgreSQL_update_Query5 = "update cuser set msgedUser = %s where id = %s"
            theCure.execute(postgreSQL_select_Query, (username,))
            user = theCure.fetchone()
            # the name is available, store it in the database and go to
            # the login page
            if password == "" and focus != "" and email == "":
                theCure.execute(postgreSQL_update_Query2, (g.cuser[1], user[5]))
                theCure.execute(postgreSQL_update_Query4, (g.cuser[3], user[5]))
                theCure.execute(postgreSQL_update_Query3, (focus, user[5]))
            if password == "" and focus == "" and email != "":
                theCure.execute(postgreSQL_update_Query3, (g.cuser[2], user[5]))
                theCure.execute(postgreSQL_update_Query2, (g.cuser[1], user[5]))
                theCure.execute(postgreSQL_update_Query4, (email, user[5]))
            if password != "" and focus == "" and email == "":
                theCure.execute(postgreSQL_update_Query3, (g.cuser[2], user[5]))
                theCure.execute(postgreSQL_update_Query4, (g.cuser[3], user[5]))
                theCure.execute(postgreSQL_update_Query2, (generate_password_hash(password), user[5]))
            if password != "" and focus == "" and email != "":
                theCure.execute(postgreSQL_update_Query3, (g.cuser[2], user[5]))
                theCure.execute(postgreSQL_update_Query4, (email, user[5]))
                theCure.execute(postgreSQL_update_Query2, (generate_password_hash(password), user[5]))
            if password != "" and focus != "" and email == "":
                theCure.execute(postgreSQL_update_Query3, (focus, user[5]))
                theCure.execute(postgreSQL_update_Query4, (g.cuser[3], user[5]))
                theCure.execute(postgreSQL_update_Query2, (generate_password_hash(password), user[5]))
            if password == "" and focus != "" and email != "":
                theCure.execute(postgreSQL_update_Query3, (focus, user[5]))
                theCure.execute(postgreSQL_update_Query4, (email, user[5]))
                theCure.execute(postgreSQL_update_Query2, (g.cuser[1], user[5]))
            elif password != "" and focus != "" and email != "":
                theCure.execute(postgreSQL_update_Query2, (generate_password_hash(password), user[5]))
                theCure.execute(postgreSQL_update_Query3, (focus, user[5]))
                theCure.execute(postgreSQL_update_Query4, (email, user[5]))
            cityV = city + " ; " + (g.cuser[4].split(" ; "))[1]
            theCure.execute(postgreSQL_update_Query5, (cityV, g.cuser[5]))
            g.db_conn.commit()
            return redirect(url_for('dashboard', username=g.cuser[0]))

        flash(error)
    # location = geolocator.reverse(strin)
    return render_template("blog/dashboard.html", posts=curse.fetchall(), messages=curs.fetchall())
@app.route("/<int:id>/update2", methods=("GET", "POST"))
def update2(id):
    """Update a post if the current user is the author."""
    curseOfLa = g.db_conn.cursor()
    curss = g.db_conn.cursor()
    cuss = g.db_conn.cursor()
    curss.execute("SELECT * FROM book;")
    postgreSQL_select_Query = "select * from cuser where id = %s"

    cuss.execute(postgreSQL_select_Query, (id,))
    user = cuss.fetchone()
    
    cur = g.db_conn.cursor()
    if request.method == 'POST':
        msgID = request.form['msgID']
        msg = request.form['msgs']
        error = None

        if error is not None:
            flash(error)
        else:
            # the name is available, store it in the database and go to
            # the login page
            cur.execute("INSERT INTO book VALUES (%s,%s,%s,%s)",(g.cuser[5], g.cuser[0], msgID, msg))
            g.db_conn.commit()
            postgreSQL_select_Query2 = "select * from cuser where username = %s"
            curseOfLa.execute(postgreSQL_select_Query2, (msgID,))
            u = curseOfLa.fetchone()
            nu = (u[4].split(" ; "))[1]
            nui = '+1' + nu
            account_sid = 'AC226ea738b271b118c82e6843b8e48427'
            auth_token = '285b6c63aeb095e084fee9c3f030202d'
            client = Client(account_sid, auth_token)

            message = client.messages \
                .create(
                     body=msg,
                     from_='+14378002075',
                     to=nui
                 )

            print(message.sid)



            port = 2525
            smtp_server = "smtp.mailtrap.io"
            login = "ee8d989802d481" # paste your login generated by Mailtrap
            password = "ad9438087ae72f" # paste your password generated by Mailtrap

            # Specify the sender’s and receiver’s email addresses:
            sender = "jadenbh12@gmail.com"
            receiver = "jadenbh12@gmail.com"

            # Type your message: use two newlines (\n) to separate the subject from the message body, and use 'f' to  automatically insert variables in the text
            message = f"""\
            Subject: Hi Mailtrap
            To: {receiver}
            From: {sender}
            This is my first message with Python."""

            try:
              # Send your message with credentials specified above
              with smtplib.SMTP(smtp_server, port) as server:
                server.login(login, password)
                server.sendmail(sender, receiver, message)
            except (gaierror, ConnectionRefusedError):
              # tell the script to report if your message was sent or which errors need to be fixed
              print('Failed to connect to the server. Bad connection settings?')
            except smtplib.SMTPServerDisconnected:
              print('Failed to connect to the server. Wrong user/password?')
            except smtplib.SMTPException as e:
              print('SMTP error occurred: ' + str(e))
            else:
              print('Sent')
            return redirect(url_for('dashboard', username=g.cuser[0]))
    # location = geolocator.reverse(strin)
    return render_template("blog/update2.html", messagess=curss.fetchall(), user=user)
@app.route('/register', methods=('GET', 'POST'))
def register():
    """Register a new user.

    Validates that the username is not already taken. Hashes the
    password for security.
    """
    cur = g.db_conn.cursor()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        focus = request.form['focus']
        email = request.form['email']
        city = request.form['city']
        num = request.form['number']
        num2 = str(num)
        r = city + " ; " + num2
        mesgeSample = ""
        nmeSample = ""
        error = None


        if error is None:
            # the name is available, store it in the database and go to
            # the login page

            cur.execute("INSERT INTO cuser VALUES (%s,%s,%s,%s,%s)",(username, generate_password_hash(password), focus, email, r))
            g.db_conn.commit()
            postgreSQL_select_Query = "select * from cuser where username = %s"

            cur.execute(postgreSQL_select_Query, (username,))
            user = cur.fetchone()
            session.clear()
            session['user_id'] = user[5]
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/register.html')
@app.route('/logout')
def logout():
    """Clear the current session, including the stored user id."""
    session.clear()
    return redirect(url_for('index'))

