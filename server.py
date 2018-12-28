from flask import Flask, render_template, request, redirect, flash, session
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$')
app = Flask(__name__)
app.secret_key = 'KeepItSecretKeepItSafe'
bcrypt = Bcrypt(app)
SCHEMA = "login_reg"


@app.route('/')
def index():
    return render_template("index.html")

@app.route("/create", methods=['POST'])
def create():
    errors = False
    if len(request.form['first_name']) < 2:
        flash("First name must contain at least two letters!")
        errors = True
    if len(request.form['last_name']) < 2:
        flash("Last name must contain at least two letters!")
        errors = True
    if len(request.form['email']) < 1:
        flash("Email cannot be blank!")
        errors = True
    elif not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!")       
        errors = True
    else:
        db = connectToMySQL(SCHEMA)
        query = 'SELECT id FROM users WHERE email = %(email)s' 
        data = {
            'email' : request.form['email']
        }
        matching_users = db.query_db(query, data)
        if len(matching_users) > 0:
            flash("Email already in use.")
            errors = True


    if len(request.form['password']) < 8:
        flash('Password must be more than 8 characters!')        
        errors = True
    elif not PASSWORD_REGEX.match(request.form['password']):
        flash('Password must contain at least one lowercase letter, one uppercase letter, and one digit!')
        errors = True

    if request.form['password'] != request.form['confirm']:
        flash('Password and confirm password must match!')
        errors = True

    if errors == True:
        return redirect('/')
    else:      
        mysql = connectToMySQL(SCHEMA)
        query = "INSERT INTO users (first_name, last_name, email, pw_hash) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(pw_hash)s);"
        data = {
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'email': request.form['email'],
            'pw_hash': bcrypt.generate_password_hash(request.form['password']),
        }
        mysql.query_db(query, data)
     
        return render_template("success.html") 

@app.route("/login", methods=['POST'])
def login():
    db = connectToMySQL(SCHEMA)
    query = 'SELECT id, email, pw_hash FROM users WHERE email = %(email)s;'
    data = {
        'email': request.form['email']
    }
    matching_users = db.query_db(query, data)
    if not matching_users:
        flash("Email or password incorrect")
        return redirect('/')

    user = matching_users[0]
    if not bcrypt.check_password_hash(user['pw_hash'], request.form['password']):
        flash("Email or password incorrect")
        return redirect('/')

    session['user_id'] = user['id']
    return render_template("success.html")

if __name__=="__main__":
    app.run(debug=True) 