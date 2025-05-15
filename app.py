from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp, jwt, datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# MongoDB config
app.config["MONGO_URI"] = "mongodb://localhost:27017/allusers"
mongo = PyMongo(app)
users = mongo.db.users

# JWT secret
JWT_SECRET = 'jwtsecret'

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('token')
        if not token:
            return redirect(url_for('login'))
        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    return redirect(url_for('signup'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        existing_user = users.find_one({'$or': [{'email': email}, {'username': username}]})
        if existing_user:
            flash("User already exists. Please login.")
            return redirect(url_for('login'))

        hashed_pass = generate_password_hash(password)
        totp_secret = pyotp.random_base32()
        users.insert_one({
            'username': username,
            'email': email,
            'password': hashed_pass,
            'totp': totp_secret
        })
        flash(f"Signup successful! Use this TOTP secret in Google Authenticator: {totp_secret}")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        token = request.form['token']

        user = users.find_one({'username': username})
        if not user or not check_password_hash(user['password'], password):
            flash("Invalid credentials")
            return redirect(url_for('login'))

        totp = pyotp.TOTP(user['totp'])
        if not totp.verify(token):
            flash("Invalid 2FA token")
            return redirect(url_for('login'))

        jwt_token = jwt.encode({
            'user': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, JWT_SECRET, algorithm="HS256")

        session['token'] = jwt_token
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/home')
@login_required
def home():
    decoded = jwt.decode(session['token'], JWT_SECRET, algorithms=["HS256"])
    return render_template('home.html', username=decoded['user'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
