from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from dotenv import load_dotenv
from datetime import timedelta
import os
from flask_cors import CORS

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://default:{os.environ.get('POSTGRES_PASSWORD')}@{os.environ.get('POSTGRES_HOST')}:5432/verceldb?sslmode=require"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY")  # add this line
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
db = SQLAlchemy(app)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)  # add this line

# CORS(app, supports_credentials=True, origins=["https://exam-mgt-sodiq-js.vercel.app/", "http://localhost:5173", "http://127.0.0.1:5173"])



class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    role = db.Column(db.String(20), default='student')

class Exam(db.Model):
    __tablename__ = "exams"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    course = db.Column(db.String(150))
    date = db.Column(db.String(30))
    time = db.Column(db.String(30))
    period = db.Column(db.String(20))
    active = db.Column(db.Boolean, default=False)
    department = db.Column(db.String(150))
    s_class = db.Column(db.String(50))

with app.app_context():
    db.create_all()


@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    role = request.json.get('role', None)

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': 'That username already exists!'}), 400

    if len(password) < 8:
        return jsonify({'message': 'Password must be at least 8 characters long'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = User(username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()

    access_token = create_access_token(identity=username)  # create a new access token

    return jsonify({
        'message': 'New user created!',
        'username': new_user.username,
        'role': new_user.role,
        'access_token': access_token  # return the access token
    }), 201


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200

    return jsonify({'message': 'Invalid username or password'}), 401



@app.route('/timetable', methods=['GET'])
# @jwt_required
def view_timetable():
    exams = Exam.query.all()
    timetable = []

    for exam in exams:
        exam_details = {
            'name': exam.name,
            'course': exam.course,
            'date': exam.date,
            'time': exam.time,
            'period': exam.period,
            'active': exam.active,
            'department': exam.department,
            'class': exam.s_class
        }
        timetable.append(exam_details)

    return jsonify({'timetable': timetable}), 200



@app.route('/set-exam', methods=['POST'])
@jwt_required()
def set_exam():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if user.role != 'staff':
        return jsonify({'message': 'Access denied'}), 403

    exam_details = request.get_json()
    name = exam_details['data']['name']
    course = exam_details['data']['course']
    date = exam_details['data']['date']
    time = exam_details['data']['time']
    period = exam_details['data']['period']
    active = exam_details['data']['active']
    department = exam_details['department']
    s_class = exam_details['class']

    new_exam = Exam(name=name, course=course, date=date, time=time, 
                    period=period, active=active, department=department, 
                    s_class=s_class
                    )

    db.session.add(new_exam)
    db.session.commit()

    return jsonify({'message': 'Exam set!'}), 200





if __name__ == '__main__':
    app.run(debug=True)