from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import time
import pandas as pd
from flask import Flask, jsonify, render_template
import ast
# from waitress import serve




app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)  # Initialize Bcrypt for hashing
df = pd.read_csv("C:/Users/acer/Quiz_Website/data/polity.csv")

@app.route('/all_users')
def all_users():
    users = User.query.all()
    user_data = [f"Username: {user.username}, Password: {user.password}" for user in users]
    return "<br>".join(user_data)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists!')
            return redirect(url_for('register'))

        # Hash the password using bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)

        # Add user to the database
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Query for the user
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template('login.html')

# Dashboard route (protected)
@app.route('/')
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        global df
        df = pd.read_csv("C:/Users/acer/Quiz_Website/data/polity.csv")
        return render_template("quiz.html")
    else:

        flash('You need to login first!')
        # time.sleep(2)
        # m = "<p>Already have an account? <a href="/login">Login here</a></p>"
        # return m
        return redirect(url_for('login'))


@app.route('/polity')
def polity():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    global df
    df = pd.read_csv("C:/Users/acer/Quiz_Website/data/polity.csv")
    return render_template('quiz.html')


@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    global df
    df = pd.read_csv("C:/Users/acer/Quiz_Website/data/history.csv")
    return render_template('quiz.html')

@app.route('/geography')
def geography():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    global df
    df = pd.read_csv("C:/Users/acer/Quiz_Website/data/geography.csv")
    return render_template('quiz.html')


# Serve question data to frontend
@app.route('/question/<int:question_id>')
def get_question(question_id):
    if question_id < len(df):
        question = df.iloc[question_id].to_dict()
        question["options"] = ast.literal_eval(question["options"])
        question["total_questions"] = len(df)
        print(question)
        return jsonify(question)
    else:
        return jsonify({"error": "No more questions"}), 404

# C://Users/acer/Quiz_Website/data

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully!')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create the database if not exists
    app.run(debug=True)
