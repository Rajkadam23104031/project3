import os
import re
import sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g, send_file
import hashlib
import json
import google.generativeai as genai
from werkzeug.security import generate_password_hash, check_password_hash
import PyPDF2
import docx
import urllib.parse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, Frame
from datetime import datetime
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.lib.utils import ImageReader
import random
import secrets
import smtplib
from email.mime.text import MIMEText
from werkzeug.utils import secure_filename
import sqlite3
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
import random
from dotenv import load_dotenv


# Initialize Flask app
app = Flask(__name_, template_folder='.', static_folder='.'_)
app.secret_key = 'your-secret-key-change-in-production'
app.config['DATABASE'] = 'interview.db'
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_SECURE'] = True
try:
    from flask_talisman import Talisman
    Talisman(app, content_security_policy=None)
except ImportError:
    print("Flask-Talisman not installed. Run: pip install flask-talisman")

load_dotenv()

app.jinja_env.globals.update(random=random.random)

# Configure Gemini API - load API key from env file
GEMINI_API_KEY = os.getenv('API_KEY')
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY not set in environment variables")

genai.configure(api_key=GEMINI_API_KEY)

oauth = OAuth(app)
# Load .env file
load_dotenv()

# Access variables
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
app.secret_key = os.getenv('FLASK_SECRET_KEY')

oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        # Enable foreign key constraints in SQLite
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db
# Database initialization
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    with app.app_context():
        db = get_db()

        # Create users table
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')




        columns = db.execute("PRAGMA table_info(users)").fetchall()
        column_names = [col['name'] for col in columns]

        # Add full_name column if missing
        if 'full_name' not in column_names:
            db.execute('ALTER TABLE users ADD COLUMN full_name TEXT')

        # Add bio column if missing
        if 'bio' not in column_names:
            db.execute('ALTER TABLE users ADD COLUMN bio TEXT')


        if 'profile_photo_path' not in column_names:
            db.execute('ALTER TABLE users ADD COLUMN profile_photo_path TEXT')

        # Create interviews table
        db.execute('''
            CREATE TABLE IF NOT EXISTS interviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                interview_type TEXT NOT NULL,
                difficulty TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        # Create responses table
        db.execute('''
            CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                interview_id INTEGER NOT NULL,
                question TEXT NOT NULL,
                answer TEXT NOT NULL,
                feedback TEXT,
                score REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (interview_id) REFERENCES interviews (id)
            )
        ''')

        db.commit()



@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function

from werkzeug.utils import secure_filename

upload_folder = os.path.join('static', 'uploads', 'profile_photos')
os.makedirs(upload_folder, exist_ok=True)  # create directory if not exists



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/commands', methods=['GET', 'POST'])
@login_required
def commands():
    userid = session.get('user_id')
    if not userid:
        return redirect(url_for('login'))

    db = get_db()

    if request.method == 'POST':
        command_text = request.form.get('command')
        if command_text:
            db.execute('INSERT INTO commands (userid, command) VALUES (?, ?)', (userid, command_text))
            db.commit()
        return redirect(url_for('commands'))

    # Include id and join for likes count and whether current user liked it
    commands = db.execute('''
        SELECT c.id, c.command, u.full_name, u.name, c.timestamp,
            (SELECT COUNT(*) FROM command_likes cl WHERE cl.command_id = c.id) AS likes,
            EXISTS(SELECT 1 FROM command_likes cl WHERE cl.command_id = c.id AND cl.user_id = ?) AS liked
        FROM commands c
        JOIN users u ON c.userid = u.id
        ORDER BY c.timestamp DESC
    ''', (userid,)).fetchall()

    commands_with_names = []
    for cmd in commands:
        user_name = cmd['full_name'] if cmd['full_name'] else cmd['name']
        commands_with_names.append({
            'id': cmd['id'],
            'command': cmd['command'],
            'user': user_name,
            'timestamp': cmd['timestamp'],
            'likes': cmd['likes'],
            'liked': bool(cmd['liked'])
        })

    return render_template('commands.html', commands=commands_with_names)


@app.route('/like_command/<int:command_id>', methods=['POST'])
@login_required
def like_command(command_id):
    user_id = session.get('user_id')
    if not user_id:
        # unauthorized requests should redirect or flash message instead of json
        flash("Please log in to like commands.", "warning")
        return redirect(url_for('commands'))

    db = get_db()

    command = db.execute('SELECT id FROM commands WHERE id = ?', (command_id,)).fetchone()
    if not command:
        flash("Command not found.", "error")
        return redirect(url_for('commands'))

    try:
        existing_like = db.execute(
            'SELECT id FROM command_likes WHERE command_id = ? AND user_id = ?', (command_id, user_id)
        ).fetchone()

        if existing_like:
            db.execute('DELETE FROM command_likes WHERE id = ?', (existing_like['id'],))
        else:
            db.execute('INSERT INTO command_likes (command_id, user_id) VALUES (?, ?)', (command_id, user_id))

        db.commit()

    except Exception as e:
        print(f"Error in like_command: {e}")
        flash("An error occurred while processing your like.", "danger")

    # Redirect back to commands page to refresh the like counts
    return redirect(url_for('commands'))
@app.route('/resume_upload', methods=['GET', 'POST'])
@login_required
def resume_upload():
    if request.method == 'POST':
        if 'resume' not in request.files:
            flash('No file selected')
            return redirect(request.url)

        file = request.files['resume']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        # Save uploaded resume
        upload_folder = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, secure_filename(file.filename))
        file.save(file_path)

        # AI Analysis to generate questions
        try:
            # ✅ Use proper resume text extraction
            resume_content = extract_text_from_resume(file_path)
            if not resume_content.strip():
                flash("Cannot read resume content. Please upload a valid PDF or DOCX.")
                return redirect(request.url)

            # Prompt for AI to generate resume-based questions
            prompt = f"""
            Analyze this resume and generate 10 interview questions based on the candidate's skills,
            projects, and experience. Return only the questions as a list.
            IMPORTANT: Return ONLY the questions, one per line, numbered 1-10. Do not include any introduction, explanations, or additional text.

            Resume Content:
            {resume_content}
            """
            model = genai.GenerativeModel('gemini-2.5-flash')
            response = model.generate_content(prompt)
            questions = response.text.strip().split('\n')
            cleaned_questions = []
            for q in questions:
                if q.strip() and any(char.isalpha() for char in q):
                    if '.' in q:
                        q = q.split('.', 1)[1].strip()
                    cleaned_questions.append(q)
            questions = cleaned_questions[:10]

            # Start Resume Interview Session
            session['interview_questions'] = questions
            session['current_question_index'] = 0
            session['interview_type'] = 'resume'
            session['difficulty'] = 'resume-based'

            db = get_db()
            cursor = db.execute('INSERT INTO interviews (user_id, interview_type, difficulty) VALUES (?, ?, ?)',
                                (session['user_id'], 'resume', 'resume-based'))
            db.commit()
            session['interview_id'] = cursor.lastrowid

            return redirect(url_for('interview', interview_type='resume', difficulty='resume-based'))

        except Exception as e:
            flash(f"Error processing resume: {str(e)}")
            return redirect(request.url)

    return render_template('resume_upload.html')

def send_otp_email(recipient, otp):
    load_dotenv()

    email_username = os.getenv('EMAIL_USERNAME')
    email_password = os.getenv('EMAIL_PASSWORD')

    msg = MIMEText(f"Your SkillMentor password reset OTP is: {otp}")
    msg['Subject'] = 'SkillMentor Password Reset OTP'
    msg['From'] = email_username
    msg['To'] = recipient

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(email_username, email_password)
        server.sendmail(msg['From'], [msg['To']], msg.as_string())


@app.route('/otp-verification', methods=['GET', 'POST'])
def otp_verification():
    if 'reset_email' not in session:
        return redirect(url_for('forgotpassword'))
    if request.method == 'POST':
        user_otp = request.form['otp']
        if user_otp == session.get('otp'):
            flash('OTP verified successfully')
            # Remove OTP from session and move to next step
            session.pop('otp', None)
            return redirect(url_for('captcha_page'))
        else:
            flash('Incorrect OTP. Try again.')
            return redirect(url_for('otp_verification'))
    return render_template('otp.html')
# AI Functions
def get_ai_questions(interview_type, difficulty, count=10):
    type_map = {
        'hr': 'HR',
        'technical': 'Technical',
        'behavioral': 'Behavioral',
        'resume': 'Resume-based'
    }

    difficulty_map = {
        'easy': 'Beginner',
        'medium': 'Intermediate',
        'hard': 'Advanced',
        'resume-based': 'Resume-based'  # ✅ Add resume-based
    }

    # For resume interview, use session questions if available
    if interview_type == 'resume' and 'interview_questions' in session:
        return session['interview_questions']

    prompt = f"Generate {count} {difficulty_map.get(difficulty, 'Beginner')} level {type_map[interview_type]} interview questions. Return only the questions as a numbered list with no additional text."

    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(prompt)
        questions = response.text.strip().split('\n')
        # Clean up questions
        cleaned_questions = []
        for q in questions:
            if q.strip() and any(char.isalpha() for char in q):
                if '.' in q:
                    q = q.split('.', 1)[1].strip()
                cleaned_questions.append(q)
        return cleaned_questions[:count]
    except Exception as e:
        print(f"Error generating questions: {e}")
        # Fallback questions
        fallbacks = {
            'hr': [
                "Tell me about a time you had to work with a difficult team member and how you handled it.",
                "Describe a situation where you had to resolve a conflict at work.",
                "How do you handle tight deadlines and multiple priorities?",
                "Tell me about a time you failed and what you learned from it.",
                "Describe your leadership style and give an example.",
                "How do you handle feedback and criticism?",
                "Tell me about a time you had to make a difficult decision.",
                "Describe a situation where you had to persuade someone.",
                "How do you prioritize your work when everything seems important?",
                "Tell me about a time you had to adapt to a significant change at work."
            ],
            'technical': [
                "Explain the concept of object-oriented programming and its main principles.",
                "What are the differences between SQL and NoSQL databases?",
                "Explain the MVC architecture pattern.",
                "What is REST API and what are its key principles?",
                "Describe the process of debugging a complex software issue.",
                "What are the advantages of using version control systems?",
                "Explain the difference between authentication and authorization.",
                "What are microservices and what are their benefits?",
                "Describe your experience with cloud computing platforms.",
                "How do you ensure the quality of your code?"
            ],
            'behavioral': [
                "Describe a situation where you had to meet a tight deadline.",
                "Tell me about a time you had to work with a diverse team.",
                "How do you handle unexpected obstacles in a project?",
                "Describe a situation where you had to take initiative.",
                "Tell me about a time you had to learn something new quickly.",
                "How do you handle working with people who have different work styles?",
                "Describe a situation where you had to give difficult feedback.",
                "Tell me about a time you had to manage a complex project.",
                "How do you stay motivated when facing challenges?",
                "Describe a situation where you had to balance multiple priorities."
            ],
            'resume': [
                "Walk me through your experience with the technologies listed on your resume.",
                "What project on your resume are you most proud of and why?",
                "How have you applied [specific skill from resume] in a real project?",
                "Describe a challenge you faced in one of the projects on your resume.",
                "What new skills have you developed recently that aren't on your resume yet?",
                "How does your experience align with the requirements of this role?",
                "What accomplishment on your resume demonstrates your problem-solving skills?",
                "How have you grown professionally from the experiences on your resume?",
                "What feedback have you received on your work that surprised you?",
                "Where do you see your skills developing in the next few years?"
            ]
        }
        return fallbacks.get(interview_type, fallbacks['hr'])


def get_ai_feedback(question, answer):
    prompt = f"""
    As an interview coach, provide concise feedback on this interview response (max 4-5 lines).

    Question: {question}
    Answer: {answer}

    Provide feedback in this format:
    Strengths: [1-2 strengths]
    Improvements: [2-3 specific improvements]
    Score: [a score from 1-10]

    Keep the feedback very concise and actionable.
    """

    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = model.generate_content(prompt)
        feedback_text = response.text.strip()

        # Extract score from feedback
        import re
        score_match = re.search(r'Score:\s*(\d+(?:\.\d+)?)', feedback_text)
        score = float(score_match.group(1)) if score_match else 7.0

        return feedback_text, score
    except Exception as e:
        return f"Error generating feedback: {str(e)}", 7.0


# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if not user:
        return redirect(url_for('login'))

    full_name = user['full_name'] if 'full_name' in user.keys() else user['name']
    bio = user['bio'] if 'bio' in user.keys() else 'Not Provided'

    return render_template('profile.html', user=user, full_name=full_name, bio=bio)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        profile_photo = user['profile_photo_path'] or 'default_profile.png'


        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_email'] = user['email']
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')

    return render_template('login.html')


# 3. GOOGLE LOGIN ROUTE
@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


# 4. GOOGLE CALLBACK ROUTE
@app.route('/google/callback')
def google_callback():
    try:
        # Get the authorization response
        token = oauth.google.authorize_access_token()
        userinfo = token.get('userinfo')

        if userinfo:
            email = userinfo['email']
            name = userinfo.get('name', '')

            db = get_db()
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

            if not user:
                # Create new user with Google OAuth
                db.execute(
                    "INSERT INTO users (email, name, password) VALUES (?, ?, ?)",
                    (email, name, 'google_oauth')
                )
                db.commit()
                user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

            # Log user in
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_email'] = user['email']

            flash('Successfully logged in with Google!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Failed to get user information from Google. Please try again.', 'error')
            return redirect(url_for('login'))

    except Exception as e:
        # Print detailed error to console (for debugging)
        print(f"Google OAuth Error: {str(e)}")
        print(f"Error Type: {type(e).__name__}")

        # Show user-friendly message on frontend
        flash('Unable to sign in with Google. Please try again or use email/password login.', 'error')
        return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if not user:
            flash('Email not registered')
            return redirect(url_for('forgot_password'))

        otp = random.randint(100000, 999999)
        session['reset_email'] = email
        session['otp'] = str(otp)
        send_otp_email(email, otp)
        flash('OTP has been sent to your email address')
        return redirect(url_for('otp_verification'))
    return render_template('gmail.html')

    # GET request



@app.route('/captcha', methods=['GET', 'POST'])
def captcha_page():
    if 'reset_email' not in session:
        return redirect(url_for('forgot_password'))

    import random

    if request.method == 'POST':
        user_captcha = request.form['captcha']
        correct_captcha = session.get('captcha_value')
        if user_captcha == correct_captcha:
            return redirect(url_for('new_password'))
        else:
            flash('Captcha incorrect. Try again.')
            return redirect(url_for('captcha_page'))

    # Generate math captcha
    a = random.randint(1, 10)
    b = random.randint(1, 10)
    session['captcha_value'] = str(a + b)
    captcha_question = f"{a} + {b} = ?"

    return render_template('captcha.html', captcha_question=captcha_question)


@app.route('/new-password', methods=['GET', 'POST'])
def new_password():
    if 'reset_email' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$'  # define regex here

        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('new_password'))

        if not re.match(password_regex, password):
            flash('Password must be at least 8 characters long, include uppercase, lowercase, number, and special character')
            return redirect(url_for('new_password'))

        hashed_password = generate_password_hash(password)
        db = get_db()
        db.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, session['reset_email']))
        db.commit()
        session.pop('reset_email', None)

        flash('Password updated successfully! Please login.')
        return redirect(url_for('login'))

    return render_template('new_password.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']

        db = get_db()
        existing_user = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()

        # Email validation
        if not (email.endswith('gmail.com') or email.endswith('apsit.edu.in')):
            flash('Please enter a valid email address')
            return redirect(url_for('register'))

        if existing_user:
            flash('Email already exists')
            return redirect(url_for('register'))
        else:
            # Password validation
            import re
            password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
            if not re.match(password_regex, password):
                flash(
                    'Password must be at least 8 characters, include uppercase, lowercase, number, and special character')
                return redirect(url_for('register'))

            hashed_password = generate_password_hash(password)
            db.execute('INSERT INTO users (email, name, password) VALUES (?, ?, ?)',
                       (email, name, hashed_password))
            db.commit()

            # ✅ AUTOMATICALLY LOG IN THE USER AFTER REGISTRATION
            # Get the newly created user
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

            # Set session variables
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_email'] = user['email']

            flash('Registration successful! Welcome to SkillMentor!', 'success')
            return redirect(url_for('dashboard'))  # ✅ Go directly to dashboard!

    return render_template('register.html')


@app.route('/profileedit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    userid = session.get('user_id')
    if not userid:
        return redirect(url_for('login'))

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (userid,)).fetchone()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        fullname = request.form.get('fullname')
        bio = request.form.get('bio')
        # Add other fields as needed

        # Update the users table with new profile info
        db.execute('UPDATE users SET name = ?, bio = ? WHERE id = ?', (fullname, bio, userid))
        db.commit()

        # Optionally update session so name reflects instantly during session
        session['username'] = fullname

        flash('Profile updated successfully!')
        return redirect(url_for('dashboard'))

    return render_template('editprofile.html', user=user)


@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()

    # Fetch the latest user info (including updated name)
    user = db.execute('SELECT full_name, name FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    user_name = user['full_name'] if 'full_name' in user.keys() and user['full_name'] else user['name']
    user = db.execute('SELECT profile_photo_path FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    profile_photo = user['profile_photo_path'] if user and 'profile_photo_path' in user.keys() else None
    # Count total interviews attempted by the user
    interview_count = db.execute('''
        SELECT COUNT(*) as total_interviews
        FROM interviews
        WHERE user_id = ?
    ''', (session['user_id'],)).fetchone()['total_interviews']



    # Fetch latest 5 interviews
    recent_interviews = db.execute('''
        SELECT id, interview_type, difficulty, created_at
        FROM interviews
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 5
    ''', (session['user_id'],)).fetchall()

    # Fetch latest TWO interviews for comparison
    latest_interviews = db.execute('''
        SELECT id FROM interviews
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 2
    ''', (session['user_id'],)).fetchall()

    if latest_interviews:
        # Calculate current (latest) interview average score
        current_interview_id = latest_interviews[0]['id']
        current_scores = db.execute('''
            SELECT score FROM responses
            WHERE interview_id = ?
        ''', (current_interview_id,)).fetchall()

        current_score = round(sum([r['score'] for r in current_scores]) / len(current_scores),
                              1) if current_scores else 0

        # Calculate previous interview average score (if exists)
        if len(latest_interviews) > 1:
            previous_interview_id = latest_interviews[1]['id']
            previous_scores = db.execute('''
                SELECT score FROM responses
                WHERE interview_id = ?
            ''', (previous_interview_id,)).fetchall()

            previous_score = round(sum([r['score'] for r in previous_scores]) / len(previous_scores),
                                   1) if previous_scores else 0
        else:
            previous_score = 0

        # Calculate improvement percentage (absolute change)
        if previous_score > 0:
            improvement = round(((current_score - previous_score) / 10) * 100, 1)
        else:
            improvement = 0

        avg_score = current_score
    else:
        avg_score = 0
        improvement = 0

    return render_template('dashboard.html',
                           user_name=user_name,
                           profile_photo=profile_photo,

                           interview_count=interview_count,
                           avg_score=avg_score,
                           improvement=improvement,
                           recent_interviews=recent_interviews
                           )

@app.route('/result/<int:interview_id>')
@login_required
def result_detail(interview_id):
    db = get_db()
    interview = db.execute('SELECT * FROM interviews WHERE id = ? AND user_id = ?', (interview_id, session['user_id'])).fetchone()
    if not interview:
        flash('Interview not found or access denied.')
        return redirect(url_for('dashboard'))

    responses = db.execute('''
        SELECT question, answer, feedback, score
        FROM responses
        WHERE interview_id = ?
        ORDER BY created_at
    ''', (interview_id,)).fetchall()

    return render_template('result_detail.html', interview=interview, responses=responses)

@app.route('/choose_type')
@login_required
def choose_type():
    db = get_db()

    # Fetch the latest interview of the user
    latest_interview = db.execute('''
        SELECT id FROM interviews
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 1
    ''', (session['user_id'],)).fetchone()

    if latest_interview:
        interview_id = latest_interview['id']
        scores_rows = db.execute('''
            SELECT score FROM responses
            WHERE interview_id = ?
            ORDER BY created_at
        ''', (interview_id,)).fetchall()
        scores = [r['score'] for r in scores_rows]
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0

        if len(scores) <= 1:
            improvement = 0
        else:
            first_score = scores[0]
            last_score = scores[-1]
            improvement = round(((last_score - first_score) / first_score) * 100, 1) if first_score else 0

        response_count = len(scores)
    else:
        avg_score = 0
        improvement = 0
        response_count = 0

    return render_template('choose_type.html',
                           user_name=session['user_name'],
                           response_count=response_count,
                           avg_score=avg_score,
                           improvement=improvement)


@app.route('/difficulty/<interview_type>')
@login_required
def difficulty(interview_type):
    return render_template('difficulty.html', interview_type=interview_type)


@app.route('/interview/<interview_type>/<difficulty>')
@login_required
def interview(interview_type, difficulty):
    if interview_type == 'resume' and 'interview_questions' in session:
        questions = session['interview_questions']  # ✅ Use uploaded resume questions
    else:
        questions = get_ai_questions(interview_type, difficulty, 10)
        session['interview_questions'] = questions  # Save to session

    session['current_question_index'] = 0
    session['interview_type'] = interview_type
    session['difficulty'] = difficulty
    session['scores'] = []

    db = get_db()
    cursor = db.execute('''
        INSERT INTO interviews (user_id, interview_type, difficulty)
        VALUES (?, ?, ?)
    ''', (session['user_id'], interview_type, difficulty))
    db.commit()
    session['interview_id'] = cursor.lastrowid

    current_question = questions[0] if questions else "No questions available"
    return render_template('interview.html',
                           question=current_question,
                           interview_type=interview_type,
                           difficulty=difficulty,
                           question_number=1,
                           total_questions=len(questions))


@app.route('/next_question', methods=['POST'])
@login_required
def next_question():
    data = request.json
    answer = data.get('answer', '')
    passed = data.get('passed', False)
    questions = session.get('interview_questions', [])
    current_index = session.get('current_question_index', 0)
    interview_id = session.get('interview_id')

    if current_index < len(questions):
        current_question = questions[current_index]

        # Get feedback for current answer
        if answer and not passed:
            feedback, score = get_ai_feedback(current_question, answer)
            session['scores'].append(score)

            db = get_db()
            db.execute('''
                INSERT INTO responses (user_id, interview_id, question, answer, feedback, score)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (session['user_id'], interview_id, current_question, answer, feedback, score))
            db.commit()
        else:
            feedback = "You passed on this question. No feedback available."
            score = 0
            session['scores'].append(score)

            db = get_db()
            db.execute('''
                INSERT INTO responses (user_id, interview_id, question, answer, feedback, score)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (session['user_id'], interview_id, current_question, "I passed on this question", feedback, score))
            db.commit()

        session['current_question_index'] = current_index + 1

        # ✅ CHECK: Is this the last question?
        if session['current_question_index'] >= len(questions):
            # Last question completed - show feedback but don't show average yet
            return jsonify({
                'completed': False,
                'last_question': True,  # ✅ New flag
                'feedback': feedback,
                'score': score,
                'message': 'All questions answered! Click "View Average Score" to see your results.'
            })

        # Not the last question - show next question
        next_question = questions[session['current_question_index']]
        return jsonify({
            'completed': False,
            'last_question': False,
            'question': next_question,
            'question_number': session['current_question_index'] + 1,
            'feedback': feedback,
            'score': score
        })

    return jsonify({'error': 'No more questions'})


@app.route('/get_average_score', methods=['GET'])
@login_required
def get_average_score():
    scores = session.get('scores', [])
    if not scores:
        return jsonify({'error': 'No scores available'}), 400

    final_score = sum(scores) / len(scores)
    return jsonify({
        'completed': True,
        'final_score': round(final_score, 1),
        'feedback': f'Interview completed! Your average score: {round(final_score, 1)}/10'
    })
@app.route('/results')
@login_required
def results():
    db = get_db()

    # Get the latest interview
    interview = db.execute('''
        SELECT * FROM interviews 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 1
    ''', (session['user_id'],)).fetchone()

    if not interview:
        flash('No interview found.')
        return redirect(url_for('dashboard'))

    # Get responses for the latest interview
    responses = db.execute('''
        SELECT r.question, r.answer, r.feedback, r.score, r.created_at
        FROM responses r
        WHERE r.interview_id = ? AND r.user_id = ?
        ORDER BY r.created_at
    ''', (interview['id'], session['user_id'])).fetchall()

    return render_template('result_detail.html', interview=interview, responses=responses)


@app.route('/analytics')
@login_required
def analytics():
    db = get_db()

    # Get the latest interview of the user
    latest_interview = db.execute('''
        SELECT id FROM interviews WHERE user_id = ? ORDER BY created_at DESC LIMIT 1
    ''', (session['user_id'],)).fetchone()

    if latest_interview:
        interview_id = latest_interview['id']

        # Get responses for this interview
        responses = db.execute('''
            SELECT created_at, score FROM responses 
            WHERE interview_id = ? 
            ORDER BY created_at
        ''', (interview_id,)).fetchall()

        dates = [r['created_at'][:10] for r in responses]
        scores = [r['score'] for r in responses]

        # Calculate overall average score
        filtered_scores = [s for s in scores if s > 0]
        overall_avg_score = round(sum(filtered_scores) / len(filtered_scores), 1) if filtered_scores else 0
    else:
        dates = []
        scores = []
        overall_avg_score = 0

    # Get type-wise averages
    type_scores = db.execute('''
        SELECT i.interview_type, AVG(r.score) as avg_score
        FROM responses r
        JOIN interviews i ON r.interview_id = i.id
        WHERE r.user_id = ? AND i.id = ?
        GROUP BY i.interview_type
    ''', (session['user_id'], interview_id if latest_interview else 0)).fetchall()

    return render_template('analytics.html',
                           dates=json.dumps(dates),
                           scores=json.dumps(scores),
                           type_scores=type_scores,
                           overall_avg_score=overall_avg_score)


@app.route('/leaderboard')
@login_required
def leaderboard():
    db = get_db()
    rounds = ['hr', 'technical', 'behavioral', 'resume']
    leaderboards = {}

    for round_name in rounds:
        leaders = db.execute('''
            SELECT u.id, u.full_name, u.name, 
                   AVG(r.score) AS avg_score,
                   (SELECT COUNT(*) 
                    FROM interviews 
                    WHERE user_id = u.id 
                    AND interview_type = ?) AS interviews_count
            FROM users u
            JOIN (
                SELECT user_id, MAX(created_at) as latest_date
                FROM interviews
                WHERE interview_type = ?
                GROUP BY user_id
            ) latest ON u.id = latest.user_id
            JOIN interviews i ON u.id = i.user_id 
                AND i.created_at = latest.latest_date
                AND i.interview_type = ?
            JOIN responses r ON i.id = r.interview_id
            GROUP BY u.id, u.full_name, u.name
            ORDER BY avg_score DESC
            LIMIT 10
        ''', (round_name, round_name, round_name)).fetchall()

        leaderboard_with_names = []
        for leader in leaders:
            user_name = leader['full_name'] if leader['full_name'] else leader['name']
            leaderboard_with_names.append({
                'name': user_name,
                'avg_score': leader['avg_score'],
                'interviews_count': leader['interviews_count']
            })

        leaderboards[round_name.title()] = leaderboard_with_names

    return render_template('leaderboard.html', leaderboards=leaderboards)

@app.route('/history')
@login_required
def history():
    db = get_db()
    responses = db.execute('''
        SELECT r.id, r.question, r.answer, r.feedback, r.score, 
               i.interview_type, i.difficulty, r.created_at
        FROM responses r
        JOIN interviews i ON r.interview_id = i.id
        WHERE r.user_id = ?
        ORDER BY r.created_at DESC
    ''', (session['user_id'],)).fetchall()
    return render_template('history.html', responses=responses)


@app.route('/delete_response/<int:response_id>', methods=['POST'])
@login_required
def delete_response(response_id):
    db = get_db()
    db.execute('DELETE FROM responses WHERE id = ? AND user_id = ?', (response_id, session['user_id']))
    db.commit()
    flash('Response deleted successfully!', 'success')
    return redirect(url_for('history'))

# Delete all user history
@app.route('/delete_all_history', methods=['POST'])
@login_required
def delete_all_history():
    db = get_db()
    db.execute('DELETE FROM responses WHERE user_id = ?', (session['user_id'],))
    db.commit()
    flash('All your history has been deleted!', 'success')
    return redirect(url_for('history'))

@app.route('/batch')
@login_required
def batch():
    db = get_db()

    latest_interview = db.execute('''
        SELECT id FROM interviews
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 1
    ''', (session['user_id'],)).fetchone()

    if latest_interview:
        interview_id = latest_interview['id']
        scores_rows = db.execute('''
            SELECT score FROM responses
            WHERE interview_id = ?
        ''', (interview_id,)).fetchall()

        scores = [r['score'] for r in scores_rows]
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0
        response_count = len(scores)
    else:
        avg_score = 0
        response_count = 0

    if avg_score >= 8:
        user_batch = 'Gold'
        color = 'gold'
        medal_img = url_for('static', filename='medals/gold.png')
    elif avg_score >= 5:
        user_batch = 'Silver'
        color = 'silver'
        medal_img = url_for('static', filename='medals/silver.png')
    else:
        user_batch = 'Bronze'
        color = 'bronze'
        medal_img = url_for('static', filename='medals/bronze.png')

    return render_template('batch.html',
                           user_batch=user_batch,
                           color=color,
                           avg_score=avg_score,
                           response_count=response_count,
                           user_name=session['user_name'],
                           medal_img=medal_img)


@app.route('/generate_certificate', methods=['POST'])
@login_required
def generate_certificate():
    data = request.get_json()
    batch = data.get('batch')
    avg_score = data.get('avg_score', 0)

    db = get_db()
    user = db.execute('SELECT full_name, name FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    user_name = user['full_name'] if user and 'full_name' in user.keys() and user['full_name'] else user['name']

    try:
        cert_dir = 'static/certificates'
        os.makedirs(cert_dir, exist_ok=True)
        safe_name = "".join(c if c.isalnum() else "_" for c in user_name) or "user"
        filename = f"{safe_name}_{batch}_certificate.pdf"
        cert_path = os.path.join(cert_dir, filename)

        logo_path = 'static/robot_logo.png'
        signature_path = 'static/signature.png'  # Your scanned/stylized signature
        certified_seal_path = 'static/certified_seal.png'  # Certified badge/seal image

        font_path = 'static/fonts/GreatVibes-Regular.ttf'
        pdfmetrics.registerFont(TTFont('GreatVibes', font_path))

        batch_lower = batch.lower() if batch else ''
        if batch_lower == 'gold':
            medal_img_path = 'static/medals/gold.png'
            accent_color = colors.HexColor("#d4af37")  # Gold
        elif batch_lower == 'silver':
            medal_img_path = 'static/medals/silver.png'
            accent_color = colors.HexColor("#c0c0c0")  # Silver
        else:
            medal_img_path = 'static/medals/bronze.png'
            accent_color = colors.HexColor("#cd7f32")  # Bronze

        c = canvas.Canvas(cert_path, pagesize=letter)
        width, height = letter

        # Light textured background simulated with subtle horizontal lines
        c.setFillColor(colors.HexColor("#f9f9f7"))
        c.rect(0, 0, width, height, fill=1, stroke=0)
        c.setStrokeColor(colors.HexColor("#eeeeeb"))
        c.setLineWidth(0.2)
        for y in range(0, int(height), 6):
            c.line(0, y, width, y)

        # Gradient approximation - soft white overlay with alpha
        c.setFillColor(colors.Color(1, 1, 1, alpha=0.7))
        c.rect(0.3 * inch, 0.3 * inch, width - 0.6 * inch, height - 0.6 * inch, fill=1, stroke=0)

        # Decorative border with batch color accent
        c.setStrokeColor(accent_color)
        c.setLineWidth(6)
        c.roundRect(0.4 * inch, 0.4 * inch, width - 0.8 * inch, height - 0.8 * inch, 28)

        # Corner flourishes using bezier curves
        c.setStrokeColor(accent_color)
        c.setLineWidth(2)
        for start, ctrl, end in [
            ((0.8 * inch, height - 0.7 * inch), (1.2 * inch, height - 0.4 * inch), (1.6 * inch, height - 0.7 * inch)),
            ((width - 0.8 * inch, height - 0.7 * inch), (width - 1.2 * inch, height - 0.4 * inch), (width - 1.6 * inch, height - 0.7 * inch)),
            ((0.8 * inch, 0.7 * inch), (1.2 * inch, 0.4 * inch), (1.6 * inch, 0.7 * inch)),
            ((width - 0.8 * inch, 0.7 * inch), (width - 1.2 * inch, 0.4 * inch), (width - 1.6 * inch, 0.7 * inch)),
        ]:
            c.bezier(start[0], start[1], ctrl[0], ctrl[1], ctrl[0], ctrl[1], end[0], end[1])

        # Logo in top-left corner with subtle shadow
        if os.path.exists(logo_path):
            c.setFillColor(colors.grey)
            c.drawImage(logo_path, 0.6 * inch + 2, height - 1.6 * inch - 2,
                        width=1.4 * inch, height=1.4 * inch, mask='auto', preserveAspectRatio=True)
            c.setFillColor(colors.white)
            c.drawImage(logo_path, 0.6 * inch, height - 1.6 * inch,
                        width=1.4 * inch, height=1.4 * inch, mask='auto', preserveAspectRatio=True)

        # Title with shadow
        title_x = width / 2
        title_y = height - 2.1 * inch
        c.setFont("Times-Bold", 34)
        c.setFillColor(colors.grey)
        c.drawCentredString(title_x + 2, title_y - 2, "Certificate of Achievement")
        c.setFillColor(colors.HexColor("#22223b"))
        c.drawCentredString(title_x, title_y, "Certificate of Achievement")

        # Certified seal near title top-right
        if os.path.exists(certified_seal_path):
            c.drawImage(certified_seal_path, width - 1.9 * inch, height - 1.9 * inch,
                        width=1.2 * inch, height=1.2 * inch, mask='auto', preserveAspectRatio=True)

        # Subtitle below title
        c.setFont("Times-Roman", 18)
        c.setFillColor(colors.HexColor("#22223b"))
        c.drawCentredString(title_x, height - 2.85 * inch, "This certificate is proudly presented to")

        # User name with shadow and accent color
        user_name_x = width / 2
        user_name_y = height - 3.65 * inch
        c.setFont("GreatVibes", 40)
        c.setFillColor(colors.grey)
        c.drawCentredString(user_name_x + 2, user_name_y - 2, user_name)
        c.setFillColor(accent_color)
        c.drawCentredString(user_name_x, user_name_y, user_name)

        # Medal image next to username
        user_name_width = stringWidth(user_name, "GreatVibes", 40)
        if os.path.exists(medal_img_path):
            img_w, img_h = 60, 60
            medal_x = user_name_x + (user_name_width / 2) + 12
            c.drawImage(medal_img_path, medal_x, user_name_y - 20, width=img_w, height=img_h, mask='auto')

        # Flourish line below username
        c.setStrokeColor(accent_color)
        c.setLineWidth(4)
        c.line(width / 2 - 2.3 * inch, height - 4.0 * inch, width / 2 + 2.3 * inch, height - 4.0 * inch)

        # Paragraph with serif font and balanced leading
        styles = getSampleStyleSheet()
        styleN = ParagraphStyle(
            'Center',
            parent=styles['Normal'],
            fontName="Times-Roman",
            fontSize=16,
            leading=22,
            alignment=1,
            textColor=colors.HexColor("#22223b")
        )
        paragraph_html = (
            f"<br/>Congratulations <b>{user_name}</b>!<br/><br/>"
            f"You have achieved <b>{batch.title()} Badge</b> status.<br/>"
            f"Average Score: <b>{avg_score}/10</b>.<br/>"
            "<br/><b>Keep striving for success!</b>"
        )
        paragraph = Paragraph(paragraph_html, styleN)
        frame = Frame(1.3 * inch, height / 2 - 1.0 * inch, width - 2.6 * inch, 2.5 * inch, showBoundary=0)
        frame.addFromList([paragraph], c)

        # Light diagonal watermark
        c.saveState()
        c.setFont("Helvetica-Bold", 48)
        c.setFillColorRGB(0.38, 0.47, 0.92, alpha=0.07)
        c.translate(width / 2, height / 2)
        c.rotate(28)
        c.drawCentredString(0, 0, "SKILLMENTOR.COM")
        c.restoreState()

        # Footer website branding in accent color
        c.setFont("Helvetica-Oblique", 12)
        c.setFillColor(accent_color)
        c.drawCentredString(width / 2, 0.85 * inch, "Powered by skillmentor.com")

        # Date bottom left in serif italic
        c.setFont("Times-Italic", 12)
        c.setFillColor(colors.HexColor("#22223b"))
        c.drawString(1.1 * inch, 0.7 * inch, f"Date: {datetime.now().strftime('%B %d, %Y')}")

        # Signature line bottom right
        line_start = width - 2.7 * inch
        line_end = width - 1 * inch
        line_y = inch
        c.setStrokeColor(colors.black)
        c.setLineWidth(1.5)
        c.line(line_start, line_y, line_end, line_y)

        # Signature image or fallback text signature
        if os.path.exists(signature_path):
            c.drawImage(signature_path, line_start + 5, line_y + 5, width=130, height=50, mask='auto', preserveAspectRatio=True)
        else:
            c.setFont("GreatVibes", 24)
            c.setFillColor(colors.HexColor('#3a0ca3'))
            c.drawString(line_start + 10, line_y + 5, "Skill Mentor")

        c.save()
        return send_file(cert_path, as_attachment=True, download_name=filename, mimetype='application/pdf')

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('index'))


def extract_text_from_resume(file_path):
    ext = file_path.rsplit('.', 1)[1].lower()
    text = ""

    if ext == 'pdf':
        with open(file_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            for page in reader.pages:
                text += page.extract_text() + "\n"
    elif ext in ['doc', 'docx']:
        doc = docx.Document(file_path)
        for para in doc.paragraphs:
            text += para.text + "\n"
    return text
# Initialize the database
init_db()

if __name__ == "__main__":

    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'), host='127.0.0.1', port=5000)
