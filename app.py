from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta
import logging
import os

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'my-static-secret-key-12345')  # Use env var in production
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_PERMANENT'] = True
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)  # Reverse proxy support

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# CSRF Protection
csrf = CSRFProtect(app)

# User class
class User(UserMixin):
    def __init__(self, id, username, password, accessible_students):
        self.id = id
        self.username = username
        self.password = password
        self.accessible_students = accessible_students  # 'all' or list of student IDs

# Hardcoded users
users = {
    'Youssef Mohamed Ahmed': User('1', 'admin', 'c29FLBV593@', 'all'),
    'YMAS': User('3', 'YMAS', 'c29FLBV593', 'all'),
    'MMM': User('2', 'MMM', '12345678', [2, 3, 5, 6, 7, 8, 10, 11, 12]),
    'SWA': User('4', 'SWA', '12345678', 'all'),
    'KHZ': User('5', 'KHZ', '12345678', [2, 3, 5, 6, 7, 8, 10, 11, 12])
}

# Hardcoded students
students = [
    {'id': 1, 'name': 'Sandy Wassim Abdullah', 'phone': '01030064939', 'address': 'Sheikh Zayed', 'instagram': 'https://www.instagram.com/sandy_wasiem12/', 'facebook': 'https://www.facebook.com/profile.php?id=61550241764159', 'dob': '2011-07-01'},
    {'id': 2, 'name': 'Karam Hazem Zaki Fouad Mushtaha', 'phone': '01009431618', 'address': 'Shobra', 'instagram': 'https://www.instagram.com/karam.hazem.10/', 'facebook': 'https://www.facebook.com/karam.hazem.10', 'dob': '2011-02-05'},
    {'id': 3, 'name': 'Mahmoud Mohamed Mahmoud', 'phone': '01090968876', 'address': 'Awsim', 'instagram': 'https://www.instagram.com/mahmoud_______2011/', 'facebook': 'https://www.facebook.com/profile.php?id=100050581157620', 'dob': '2011-08-28'},
    {'id': 4, 'name': 'Layan Wael Mohamed', 'phone': '01554918118', 'address': 'Faisal Mariouteya', 'instagram': '', 'facebook': 'https://www.facebook.com/lian.wael.14', 'dob': '2011-08-01'},
    {'id': 5, 'name': 'Malek Hany Abdelal', 'phone': '01122206125', 'address': 'Faisal Mariouteya', 'instagram': 'https://www.instagram.com/itz_____malek/', 'facebook': 'https://www.facebook.com/profile.php?id=100055797635744', 'dob': '2011-10-11'},
    {'id': 6, 'name': 'Youssef Mohamed Ahmed Sayed Ali', 'phone': '01155201219', 'address': 'Sheikh Zayed, 9th district, 1st Neighbourhoud, Villa 103, 2nd Floor, Appartment no. 7', 'instagram': 'https://www.instagram.com/joe__is__here/', 'facebook': 'https://www.facebook.com/profile.php?id=61553419564295', 'dob': '2011-05-28'},
    {'id': 7, 'name': 'Hazem Ahmed Hamed', 'phone': '01282932266', 'address': 'Sheikh Zayed, 9th district, 1st neighbourhood, villa 48', 'instagram': '', 'facebook': 'https://www.facebook.com/share/18mufQZ6ku/', 'dob': '2011-09-11'},
    {'id': 8, 'name': 'Asser Omar Elfarouk', 'phone': '', 'address': 'Awsim', 'instagram': '', 'facebook': '', 'dob': '2011-11-18'},
    {'id': 9, 'name': 'Eman Khaled Sobhy', 'phone': '01069090855', 'address': 'Al Mansouria', 'instagram': 'https://www.instagram.com/emy_khaled24/', 'facebook': 'https://www.facebook.com/profile.php?id=100033184364731', 'dob': '2011-03-21'},
    {'id': 10, 'name': 'Rayan Hossam Abdullah', 'phone': '01028291900', 'address': 'El Warraq', 'instagram': 'https://www.instagram.com/11rayanhossam/', 'facebook': 'https://www.facebook.com/profile.php?id=100077890854656', 'dob': '2011-06-05'},
    {'id': 11, 'name': 'Yassin Ahmed Saber', 'phone': '', 'address': 'Faisal', 'instagram': 'https://www.instagram.com/yassin_priv157/', 'facebook': '', 'dob': '2011-07-15'},
    {'id': 12, 'name': 'Zeyad Ossama', 'phone': '01114449420', 'address': 'Hadayiq Alahram', 'instagram': 'https://www.instagram.com/https__zeyad/', 'facebook': 'https://www.facebook.com/zeyad.osama.526438', 'dob': '2011-08-16'},
    {'id': 13, 'name': 'Nour Ahmed Bayoumi', 'phone': '01091651913', 'address': 'Sheikh Zayed, Jannat Zayed', 'instagram': 'https://www.instagram.com/nour_bayy/', 'facebook': 'https://www.facebook.com/profile.php?id=100005839187064', 'dob': ''},
    {'id': 14, 'name': 'Retal Amr', 'phone': '01157301291', 'address': 'Sheikh Zayed, Palm Hills', 'instagram': 'https://www.instagram.com/retalamr_09/', 'facebook': 'https://www.facebook.com/profile.php?id=61561025622171', 'dob': '2011-02-01'},
    {'id': 15, 'name': 'Kenzy Ahmed', 'phone': '01557831722', 'address': 'Hadayiq Alahram', 'instagram': 'https://www.instagram.com/kenzyahmed870/', 'facebook': 'https://www.facebook.com/kenzyAhmed22011', 'dob': '2011-02-27'},
]
students.sort(key=lambda x: x['name'])

# User activity tracking
user_activity = {}

# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    for user in users.values():
        if user.id == user_id:
            return user
    return None

# Session expiration check
def check_session_expiration():
    if current_user.is_authenticated:
        last_activity = session.get('last_activity')
        if last_activity and (datetime.now() - datetime.fromtimestamp(last_activity)) > app.config['PERMANENT_SESSION_LIFETIME']:
            if current_user.username in user_activity:
                user_activity[current_user.username]['logout_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logout_user()
            session.clear()
            logger.info("Session expired for user")
        session['last_activity'] = datetime.now().timestamp()
        session.modified = True

@app.before_request
def before_request():
    check_session_expiration()

# Custom error handler for 500 errors
@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal Server Error: {str(e)}")
    return "Something went wrong on our end. Please try again later.", 500

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
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
    except Exception as e:
        logger.error(f"Error in login: {str(e)}")
        return "Internal Server Error", 500

@app.route('/logout')
@login_required
def logout():
    try:
        if current_user.username in user_activity:
            user_activity[current_user.username]['logout_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logout_user()
        session.clear()
        logger.info("User logged out")
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error in logout: {str(e)}")
        return "Internal Server Error", 500

@app.route('/')
@login_required
def index():
    try:
        if current_user.username == 'admin':
            return render_template('admin_dashboard.html', users=users, user_activity=user_activity)
        filtered_students = students if current_user.accessible_students == 'all' else [
            s for s in students if s['id'] in current_user.accessible_students
        ]
        return render_template('index.html', students=filtered_students)
    except Exception as e:
        logger.error(f"Error in index: {str(e)}")
        return "Internal Server Error", 500

@app.route('/student', methods=['POST'])
@login_required
def student_detail():
    try:
        student_id = request.form.get('student_id')
        if not student_id:
            logger.warning("Missing student_id in request")
            return 'Missing student_id', 400
        try:
            student_id = int(student_id)
        except ValueError:
            logger.warning(f"Invalid student_id: {student_id}")
            return 'Invalid student_id', 400
        student = next((s for s in students if s['id'] == student_id), None)
        if not student:
            logger.warning(f"Student not found: {student_id}")
            return 'Student not found', 404
        if current_user.accessible_students != 'all' and student['id'] not in current_user.accessible_students:
            logger.warning(f"Unauthorized access attempt by {current_user.username} for student {student_id}")
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
    try:
        if current_user.username != 'admin':
            logger.warning(f"Unauthorized clear_activity attempt by {current_user.username}")
            return 'Unauthorized', 403
        user_activity.clear()
        flash('User activity cleared')
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Error in clear_activity: {str(e)}")
        return "Internal Server Error", 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)