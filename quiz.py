from flask import Flask, jsonify, render_template
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
import pandas as pd
import ast
app = Flask(__name__)

#
# Load your quiz data (example DataFrame with columns: 'question', 'options', 'answer')
df = pd.read_csv("data/polity.csv")
# quiz_data = {
#     'question': ['What is the capital of France?', 'What is 2 + 2?', 'What is the color of the sky?'],
#     'options': [['Paris', 'London', 'Berlin', 'Rome'], ['3', '4', '5', '6'], ['Blue', 'Red', 'Green', 'Yellow']],
#     'answer': ['Paris', '4', 'Blue']
# }
# df = pd.DataFrame(quiz_data)
# df.to_csv('output.csv', index=False)
# Serve the home page
@app.route('/')
def index():
    return render_template('quiz.html')

@app.route('/history')
def history():
    global df
    df = pd.read_csv("data/history.csv")
    return render_template('quiz.html')

@app.route('/geography')
def geography():
    global df
    df = pd.read_csv("data/geography.csv")
    return render_template('quiz.html')


# Serve question data to frontend
@app.route('/question/<int:question_id>')
def get_question(question_id):
    if question_id < len(df):
        question = df.iloc[question_id].to_dict()
        question["options"] = ast.literal_eval(question["options"])
        question["total_questions"] = len(df)
        # print(question)
        return jsonify(question)
    else:
        return jsonify({"error": "No more questions"}), 404

if __name__ == '__main__':
    app.run(debug=False)
