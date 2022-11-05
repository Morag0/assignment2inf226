from http import HTTPStatus
from flask import Flask, abort, request, send_from_directory, make_response, render_template
from werkzeug.datastructures import WWWAuthenticate
import flask
import bcrypt
from login_form import LoginForm
from json import dumps, loads
from base64 import b64decode
import sys
import apsw
from apsw import Error
from pygments import highlight
from pygments.lexers import SqlLexer
from pygments.formatters import HtmlFormatter
from pygments.filters import NameHighlightFilter, KeywordCaseFilter
from pygments import token;
from threading import local
from markupsafe import escape

tls = local()
inject = "'; insert into messages (sender,message) values ('foo', 'bar');select '"
cssData = HtmlFormatter(nowrap=True).get_style_defs('.highlight')
conn = None

# Set up app
app = Flask(__name__)
# The secret key enables storing encrypted session data in a cookie (make a secure random key for this!)
app.secret_key = 'mY s3kritz'

# Add a login manager to the app
import flask_login
from flask_login import login_required, login_user, logout_user
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

users = {'alice' : {'password' : 'password123', 'token' : 'tiktok'},
         'bob' : {'password' : 'bananas'}
         }

allowed_characters=['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','1','2','3','4','5','6','7','8','9','0',',',' ','.','?','!']

salt = bcrypt.gensalt()
# Class to store user info
# UserMixin provides us with an `id` field and the necessary
# methods (`is_authenticated`, `is_active`, `is_anonymous` and `get_id()`)
class User(flask_login.UserMixin):
    pass


# This method is called whenever the login manager needs to get
# the User object for a given user id
@login_manager.user_loader
def user_loader(user_id):
    if user_id not in users:
        return

    # For a real app, we would load the User from a database or something
    user = User()
    user.id = user_id
    return user

# This method is called to get a User object based on a request,
# for example, if using an api key or authentication token rather
# than getting the user name the standard way (from the session cookie)
@login_manager.request_loader
def request_loader(request):
    # Even though this HTTP header is primarily used for *authentication*
    # rather than *authorization*, it's still called "Authorization".
    auth = request.headers.get('Authorization')

    # If there is not Authorization header, do nothing, and the login
    # manager will deal with it (i.e., by redirecting to a login page)
    if not auth:
        return

    (auth_scheme, auth_params) = auth.split(maxsplit=1)
    auth_scheme = auth_scheme.casefold()
    if auth_scheme == 'basic':  # Basic auth has username:password in base64
        (uid,passwd) = b64decode(auth_params.encode(errors='ignore')).decode(errors='ignore').split(':', maxsplit=1)
        print(f'Basic auth: {uid}:{passwd}')
        u = users.get(uid)
        if u: # and check_password(u.password, passwd):
            return user_loader(uid)
    elif auth_scheme == 'bearer': # Bearer auth contains an access token;
        # an 'access token' is a unique string that both identifies
        # and authenticates a user, so no username is provided (unless
        # you encode it in the token – see JWT (JSON Web Token), which
        # encodes credentials and (possibly) authorization info)
        print(f'Bearer auth: {auth_params}')
        for uid in users:
            if users[uid].get('token') == auth_params:
                return user_loader(uid)
    # For other authentication schemes, see
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication

    # If we failed to find a valid Authorized header or valid credentials, fail
    # with "401 Unauthorized" and a list of valid authentication schemes
    # (The presence of the Authorized header probably means we're talking to
    # a program and not a user in a browser, so we should send a proper
    # error message rather than redirect to the login page.)
    # (If an authenticated user doesn't have authorization to view a page,
    # Flask will send a "403 Forbidden" response, so think of
    # "Unauthorized" as "Unauthenticated" and "Forbidden" as "Unauthorized")
    abort(HTTPStatus.UNAUTHORIZED, www_authenticate = WWWAuthenticate('Basic realm=inf226, Bearer'))

def pygmentize(text):
    if not hasattr(tls, 'formatter'):
        tls.formatter = HtmlFormatter(nowrap = True)
    if not hasattr(tls, 'lexer'):
        tls.lexer = SqlLexer()
        tls.lexer.add_filter(NameHighlightFilter(names=['GLOB'], tokentype=token.Keyword))
        tls.lexer.add_filter(NameHighlightFilter(names=['text'], tokentype=token.Name))
        tls.lexer.add_filter(KeywordCaseFilter(case='upper'))
    return f'<span class="highlight">{highlight(text, tls.lexer, tls.formatter)}</span>'

@app.route('/favicon.ico')
def favicon_ico():
    return send_from_directory(app.root_path, 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/favicon.png')
def favicon_png():
    return send_from_directory(app.root_path, 'favicon.png', mimetype='image/png')


@app.route('/')
@app.route('/index.html')
@login_required
def index_html():
    return send_from_directory(app.root_path,
                        'index.html', mimetype='text/html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.is_submitted():
        print(f'Received form: {"invalid" if not form.validate() else "valid"} {form.form_errors} {form.errors}')
        print(request.form)
    if form.validate_on_submit():
        # TODO: we must check the username and password
        username = form.username.data
        password = form.password.data
        u = users.get(username)
        if u: # and check_password(u.password, password):
            user = user_loader(username)
            
            # automatically sets logged in session cookie
            login_user(user)

            flask.flash('Logged in successfully.')

            next = flask.request.args.get('next')
    
            # is_safe_url should check if the url is safe for redirects.
            # See http://flask.pocoo.org/snippets/62/ for an example.
            if False and not is_safe_url(next):
                return flask.abort(400)

            return flask.redirect(next or flask.url_for('index'))
    return render_template('./login.html', form=form)

# This function allows the user to be sent back to the login screen
@app.route('/logout', methods=['POST', 'GET'])
def logout():
    logout_user()
    return 'LOGGED OUT'

@app.get('/search')
def search():
    query = request.args.get('q') or request.form.get('q') or '*'
    stmt = f"SELECT * FROM messages WHERE message GLOB ? AND (sender = ? OR recipient = ?)"
    # result = f"Query: {pygmentize(stmt)}\n"
    try:
        c = conn.execute(stmt, (query, flask_login.current_user.id, flask_login.current_user.id))
        rows = c.fetchall()
        result = 'Result:\n'
        for row in rows:
            result = f'{result}    {dumps(row)}\n'
        c.close()
        return result
    except Error as e:
        return (f'{result}ERROR: {e}', 500)

@app.route('/send', methods=['POST','GET'])
def send():
    try:
        sender = request.args.get('sender') or request.form.get('sender')
        message = request.args.get('message') or request.args.get('message')
        recipient = request.args.get('recipient') or request.form.get('recipient')
        recipients = recipient.split(", ")
        if len(message) > 400 :
            return f'ERROR: Your message is too long!'
        if any(x not in allowed_characters for x in message):
            return f'ERROR: INVALID CHARACTERS IN MESSAGE'
        if not sender or not message:
            return f'ERROR: missing sender or message'
        if flask_login.current_user.id != sender:
            return f'ERROR: Sender is not equal to user!'
        for x in recipients:
            if not userExist(x):
                return f'ERROR: Recipient does not exists!'
        stmt = f"INSERT INTO messages (sender, recipient, message) values (?, ?, ?);"
        result = f"Query: {pygmentize(stmt)}\n"
        conn.execute(stmt, (sender, recipient, message))
        return f'From: {sender} To: {recipient}'+'\n'+f'Message: {message}'
    except Error as e:
        return f'{result}ERROR: {e}'

# Simple function to check if the user exists in the database
def userExist(username):
    stmt = f"SELECT * FROM users WHERE username = '{username}'"
    userInfo = c.execute(stmt).fetchall()
    return userInfo != []

@app.get('/announcements')
def announcements():
    try:
        stmt = f"SELECT author,text FROM announcements;"
        c = conn.execute(stmt)
        anns = []
        for row in c:
            anns.append({'sender':escape(row[0]), 'message':escape(row[1])})
        return {'data':anns}
    except Error as e:
        return {'error': f'{e}'}

@app.get('/coffee/')
def nocoffee():
    abort(418)

@app.route('/coffee/', methods=['POST','PUT'])
def gotcoffee():
    return "Thanks!"

@app.get('/highlight.css')
def highlightStyle():
    resp = make_response(cssData)
    resp.content_type = 'text/css'
    return resp

try:
    conn = apsw.Connection('./tiny.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id integer UNIQUE PRIMARY KEY, 
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        message TEXT NOT NULL);''')
    c.execute('''CREATE TABLE IF NOT EXISTS announcements (
        id integer UNIQUE PRIMARY KEY, 
        author TEXT NOT NULL,
        text TEXT NOT NULL);''')
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id integer UNIQUE PRIMARY KEY, 
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        token TEXT);''')
    #Set to True if you want to create new user entries
    if False:
        pswrd = bcrypt.hashpw('password123'.encode('utf-8'), salt).decode('utf-8')
        c.execute(f'''INSERT INTO users (username, password, token) VALUES ('alice', '{pswrd}', 'tiktok');''')
        pswrd = bcrypt.hashpw('bananas'.encode('utf-8'), salt).decode('utf-8')
        c.execute(f'''INSERT INTO users (username, password) VALUES ('bob', '{pswrd}');''')
except Error as e:
    print(e)
    sys.exit(1)

