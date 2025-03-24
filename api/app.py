from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.middleware.proxy_fix import ProxyFix
import secrets
from datetime import datetime, timedelta
import logging
import os

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'my-static-secret-key-12345')  # Use env var in production
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # 30-minute session lifetime
app.config['SESSION_PERMANENT'] = True
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)  # Reverse proxy support

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class
class User(UserMixin):
    def __init__(self, id, username, password, accessible_students):
        self.id = id
        self.username = username
        self.password = password
        self.accessible_students = accessible_students  # 'all' or list of student IDs

# Hardcoded data (replace with database in production)
users = {
    'admin': User('1', 'admin', 'c29FLBV593', 'all'),
    'YMAS' : User('3',  'YMAS', 'c29FLBV593', 'all'),#Youssef Mohamed Ahmed
    'MMM' : User('2', 'MMM', 'R9T5B2L8', [3, 2, 6, 5]),#Mahmoud Mohamed Mahmoud
    'SWA': User('4', 'SWA', '3K7M4N1Q', [1, 4]),#Sandy Wassim Abdullah
    'KHZ': User('5','KHZ', 'W6X2Y9Z4', [3, 2, 6, 5])#Karam Hazem Zaki
}

students = [
    {'id': 1,
 'name': 'Sandy Wassim Abdullah',
 'phone': '01030064939',
 'address': 'Sheikh Zayed',
 'instagram': 'https://www.instagram.com/sandy_wasiem12/',
 'facebook': 'https://www.facebook.com/profile.php?id=61550241764159',
 'dob': '2011-07-01',
 'car': ''},
    {'id': 2, 'name': 'Karam Hazem Zaki Fouad Mushtaha', 'phone': '01009431618', 'address': 'Shobra', 'instagram': 'https://www.instagram.com/karam.hazem.10/', 'facebook': 'https://www.facebook.com/karam.hazem.10', 'dob': '2011-02-05', 'car': ''},
    {'id': 3, 'name': 'Mahmoud Mohamed Mahmoud', 'phone': '01090968876', 'address': 'Awsim', 'instagram': 'https://www.instagram.com/mahmoud_______2011/', 'facebook': 'https://www.facebook.com/profile.php?id=100050581157620', 'dob': '2011-08-28', 'car': 'Hyundai Elantra 2020'},
    {'id': 4, 'name': 'Layan Wael Mohamed', 'phone': '01554918118', 'address': 'Faisal Mariouteya', 'instagram': '', 'facebook': 'https://www.facebook.com/lian.wael.14', 'dob': '2011-08-01', 'car': ''},
    {'id': 5, 'name': 'Malek Hany Abdelal', 'phone': '01122206125', 'address': 'Faisal Mariouteya', 'instagram': 'https://www.instagram.com/itz_____malek/', 'facebook': 'https://www.facebook.com/profile.php?id=100055797635744', 'dob': '2011-10-11', 'car': ''},
    {'id': 6, 'name': 'Youssef Mohamed Ahmed Sayed Ali', 'phone': '01155201219', 'address': 'Sheikh Zayed', 'instagram': 'https://www.instagram.com/joe__is__here/', 'facebook': 'https://www.facebook.com/profile.php?id=61553419564295', 'dob': '2011-05-28', 'car': 'Mitushibi Eclipse Cross 2024'},
    {'id': 7, 'name': 'Hazem Ahmed Hamed','phone':'01282932266' , 'address': ' Sheikh Zayed, 9th district, 1st neighbourhood, villa 48','instagram':'','facebook':'https://www.facebook.com/share/18mufQZ6ku/' ,'dob':'2011-09-11', 'car':'toyota corolla 2021'}
]

# User activity tracking
user_activity = {}

# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    for user in users.values():
        if user.id == user_id:
            return user
    return None

# Token generation and validation
def generate_token(student_id):
    token = secrets.token_urlsafe(16)
    session[f'token_{student_id}'] = {'token': token, 'expires': (datetime.now() + timedelta(minutes=5)).timestamp()}
    return token

def validate_token(student_id, token):
    token_data = session.get(f'token_{student_id}')
    return token_data and token_data['token'] == token and datetime.now().timestamp() <= token_data['expires']

# Session expiration check
def check_session_expiration():
    if current_user.is_authenticated:
        last_activity = session.get('last_activity')
        if last_activity and (datetime.now() - datetime.fromtimestamp(last_activity)) > app.config['PERMANENT_SESSION_LIFETIME']:
            if current_user.username in user_activity:
                user_activity[current_user.username]['logout_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logout_user()
            session.clear()
        session['last_activity'] = datetime.now().timestamp()
        session.modified = True

@app.before_request
def before_request():
    check_session_expiration()

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Username and password are required')
            return render_template('login.html')
        user = next((u for u in users.values() if u.username == username and u.password == password), None)
        if user:
            login_user(user)
            session['last_activity'] = datetime.now().timestamp()
            user_activity[user.username] = {
                'login_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'logout_time': None,
                'students_checked': []
            }
            logger.info(f"User {user.username} logged in")
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    if current_user.username in user_activity:
        user_activity[current_user.username]['logout_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logout_user()
    session.clear()
    logger.info("User logged out")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    try:
        if current_user.username == 'Youssef Mohamed Ahmed':
            return render_template('admin_dashboard.html', users=users, user_activity=user_activity)
        filtered_students = students if current_user.accessible_students == 'all' else [
            s for s in students if s['id'] in current_user.accessible_students
        ]
        tokens = {student['id']: generate_token(student['id']) for student in filtered_students}
        return render_template('index.html', students=filtered_students, tokens=tokens)
    except Exception as e:
        logger.error(f"Error in index: {str(e)}")
        return "Internal Server Error", 500

@app.route('/student', methods=['POST'])
@login_required
def student_detail():
    try:
        student_id = request.form.get('student_id')
        token = request.form.get('token')
        if not student_id or not token:
            return 'Missing student_id or token', 400
        try:
            student_id = int(student_id)
        except ValueError:
            return 'Invalid student_id', 400
        if not validate_token(student_id, token):
            return 'Invalid or expired token', 403
        student = next((s for s in students if s['id'] == student_id), None)
        if not student:
            return 'Student not found', 404
        if current_user.accessible_students != 'all' and student['id'] not in current_user.accessible_students:
            return 'Unauthorized', 403
        if current_user.username in user_activity:
            user_activity[current_user.username]['students_checked'].append({
                'id': student_id,
                'name': student['name'],
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
        return render_template('student.html', student=student)
    except Exception as e:
        logger.error(f"Error in student_detail: {str(e)}")
        return "Internal Server Error", 500

@app.route('/clear_activity', methods=['POST'])
@login_required
def clear_activity():
    if current_user.username != 'Youssef Mohamed Ahmed':
        return 'Unauthorized', 403
    user_activity.clear()
    flash('User activity cleared')
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)