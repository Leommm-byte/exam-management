from flask import Flask, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os


load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = {os.environ.get("SECRET_KEY")}
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://default:{os.environ.get('POSTGRES_PASSWORD')}@{os.environ.get('POSTGRES_HOST')}:5432/verceldb?sslmode=require"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

bcrypt = Bcrypt(app)


class User(UserMixin, db.Model):
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
    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return 'Welcome to the Flask Login Example!'


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.json['username']
        password = request.json['password']
        role = request.json['role']

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'message': 'That username already exists!'}), 400

        # Check if password meets requirements
        if len(password) < 8:
            return jsonify({'message': 'Password must be at least 8 characters long'}), 400

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create a new user
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return jsonify({'message': 'New user created!'}), 201
    
    return jsonify({'message': 'Please fill out the form'}), 400


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.json['username']
        password = request.json['password']

        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return jsonify({'message': 'You are now logged in'}), 200
        
        return jsonify({'message': 'Invalid username or password'}), 401

    return jsonify({'message': 'Please fill out the form'}), 400


@app.route('/set-exam', methods=['POST'])
@login_required
def set_exam():
    try:
        if current_user.role != 'staff':
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
    
    except Exception as e:
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500
    

@app.route('/timetable')
@login_required
def timetable():
    try:
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

    except Exception as e:
        return jsonify({'message': 'An error occurred', 'error': str(e)}), 500


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)