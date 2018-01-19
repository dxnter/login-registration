import re, os, md5, binascii
from flask import Flask, render_template, redirect, request, session, flash
from mysqlconnection import MySQLConnector


app = Flask(__name__)
app.secret_key = os.urandom(24)
mysql = MySQLConnector(app, 'users')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    errors = False

    if re.match("^[a-zA-Z]{2,}$", request.form['first_name']) == None:
        flash('Please enter a first name', 'register')
        errors = True

    if re.match("^[a-zA-Z]{2,}$", request.form['last_name']) == None:
        flash('Please enter a last name', 'register')
        errors = True

    if re.match("(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", request.form['email']) == None:
        flash('Not a valid email', 'register')
        errors = True

    if len(request.form['password']) <= 8:
        flash('Passwords need to be at least 8 characters', 'register')
        errors = True

    if request.form['password'] != request.form['confirm_password']:
        flash('Passwords don\'t match', 'register')
        errors = True

    if errors:
        return redirect('/')

    session['first_name'] = request.form['first_name']
    session['email'] = request.form['email']
    last_name = request.form['last_name']
    password = request.form['password']
    salt = binascii.b2a_hex(os.urandom(15))
    hashed_pw = md5.new(password + salt).hexdigest()

    insert_query = "INSERT INTO users (first_name, last_name, email, password, salt, created_at) VALUES (:first_name, :last_name, :email, :hashed_pw, :salt, NOW())"
    query_data = {'first_name': session['first_name'], 'last_name': last_name, 'email': session['email'], 'hashed_pw': hashed_pw, 'salt': salt}
    mysql.query_db(insert_query, query_data)

    return redirect('/success')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return redirect('/')

    email = request.form['email']
    password = request.form['password']
    user_query = "SELECT * FROM users WHERE users.email = :email LIMIT 1"
    query_data = {'email': email}
    user = mysql.query_db(user_query, query_data)
    if len(user) != 0:
        encrypted_password = md5.new(password + user[0]['salt']).hexdigest()
        if user[0]['password'] == encrypted_password:
            session['id'] = user[0]['id']
            session['first_name'] = user[0]['first_name']
            return render_template('success.html')
        else:
            flash('Invalid password', 'login')
            return redirect('/')
    else:
        flash('Invalid email', 'login')
        return redirect('/')
    

@app.route('/success', methods=['GET'])
def success():
    return render_template('success.html')


app.run(debug=True)