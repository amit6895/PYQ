

from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from flask_bcrypt import Bcrypt
import pandas as pd
import ast

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(minutes=30)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)  # Initialize Bcrypt for hashing

# User model
@app.route('/all_users')
def all_users():
    users = User.query.all()
    user_data = [f"Username: {user.username}, Password: {user.password}" for user in users]
    return "<br>".join(user_data)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


class UserAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    question_id = db.Column(db.Integer, nullable=False)
    question_text = db.Column(db.String, nullable=False)
    selected_answer = db.Column(db.String, nullable=False)
    correct_answer = db.Column(db.String, nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)


@app.route('/save_attempt', methods=['POST'])
def save_attempt():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized access'}), 403

    data = request.json
    user_id = session['user_id']
    category = data['category']
    question_id = data['question_id']
    question_text = data['question_text']
    selected_answer = data['selected_answer']
    correct_answer = data['correct_answer']
    is_correct = selected_answer == correct_answer

    # Save the attempt in the database
    attempt = UserAttempt(
        user_id=user_id,
        category=category,
        question_id=question_id,
        question_text=question_text,
        selected_answer=selected_answer,
        correct_answer=correct_answer,
        is_correct=is_correct
    )
    db.session.add(attempt)
    db.session.commit()

    return jsonify({'message': 'Attempt saved successfully'})


@app.route('/view_attempts', methods=['GET'])
def view_attempts():
    if 'user_id' not in session:
        flash('You need to log in first!')
        return redirect(url_for('login'))

    user_id = session['user_id']
    filter_type = request.args.get('filter', 'all')  # 'all', 'correct', or 'wrong'

    # Query the database for user attempts
    if filter_type == 'correct':
        attempts = UserAttempt.query.filter_by(user_id=user_id, is_correct=True).all()
    elif filter_type == 'wrong':
        attempts = UserAttempt.query.filter_by(user_id=user_id, is_correct=False).all()
    else:
        attempts = UserAttempt.query.filter_by(user_id=user_id).all()

    return render_template('view_attempts.html', attempts=attempts, filter_type=filter_type)

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
            session['username'] = user.username
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template('login.html')

# Dashboard route (protected)
@app.route('/')
@app.route('/home')
def dashboard():
    if 'user_id' in session:
        user_id = session.get('user_id')
        username = session.get('username')
        print(user_id)  # For debugging purposes
        return render_template('home.html', user_id=user_id , username = username)
    else:
        flash('You need to login first!')
        return render_template('home.html', user_id=None)


# Polity route
@app.route('/polity')
def polity():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Load the Polity CSV data locally
    polity_df = pd.read_csv("C:/Users/acer/Quiz_Website/data/polity.csv")
    return render_template('quiz.html', questions=polity_df.to_dict(orient='records'), subject="Polity")

# History route
@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Load the History CSV data locally
    history_df = pd.read_csv("C:/Users/acer/Quiz_Website/data/history.csv")
    return render_template('quiz.html', questions=history_df.to_dict(orient='records'), subject="History")

# Geography route
@app.route('/geography')
def geography():
    if 'user_id' not in session:
        print(session)
        return redirect(url_for('login'))

    # Load the Geography CSV data locally
    geography_df = pd.read_csv("C:/Users/acer/Quiz_Website/data/geography.csv")
    return render_template('quiz.html', questions=geography_df.to_dict(orient='records'), subject="Geography")

# Serve question data to frontend
@app.route('/question/<category>/<int:question_id>')
def get_question(category, question_id):
    # Load the correct CSV file based on the category
    if category == "polity":
        df = pd.read_csv("C:/Users/acer/Quiz_Website/data/polity.csv")
    elif category == "history":
        df = pd.read_csv("C:/Users/acer/Quiz_Website/data/history.csv")
    elif category == "geography":
        df = pd.read_csv("C:/Users/acer/Quiz_Website/data/geography.csv")
    else:
        return jsonify({"error": "Invalid category"}), 400


    print(session)
    if question_id < len(df):
        question = df.iloc[question_id].to_dict()
        question["options"] = ast.literal_eval(question["options"])
        question["total_questions"] = len(df)
        return jsonify(question)
    else:
        return jsonify({"error": "No more questions"}), 404

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
