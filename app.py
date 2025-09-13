from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pyotp
import os
import re

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'PASSWORD_IS_SECRET'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Initialize database
db = SQLAlchemy(app)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20))  # Malaysian phone number
    otp_secret = db.Column(db.String(32), nullable=False)
    security_question = db.Column(db.String(200), nullable=False)
    security_answer_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def generate_otp_secret(self):
        self.otp_secret = pyotp.random_base32()
        return self.otp_secret
    
    def get_otp(self):
        totp = pyotp.TOTP(self.otp_secret)
        return totp.now()
    
    def verify_otp(self, otp):
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(otp)
    
    def set_security_answer(self, answer):
        self.security_answer_hash = generate_password_hash(answer)
    
    def check_security_answer(self, answer):
        return check_password_hash(self.security_answer_hash, answer)
    
class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(150), nullable=False)
    encrypted_password = db.Column(db.String(500), nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Utility functions
def is_valid_email(email):
    """email verification"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_phone(phone):
    """phone verification"""
    pattern = r'^(\+?60|0)(1[0-9]{8,9}|[2-9][0-9]{7,8})$'
    return re.match(pattern, phone) is not None

def format_malaysia_phone(phone):
    """format phone to Malaysia standard"""
    if phone.startswith('0'):
        return '6' + phone  # 01x-xxxxxxx -> 601x-xxxxxxx
    elif phone.startswith('+60'):
        return phone[1:]  # +601x-xxxxxxx -> 601x-xxxxxxx
    elif phone.startswith('60'):
        return phone  # 601x-xxxxxxx
    else:
        return '60' + phone  # 1x-xxxxxxx -> 601x-xxxxxxx

def encrypt_password(password, master_key):
    """simple XOR encryption function"""
    encrypted = ''.join(chr(ord(c) ^ ord(master_key[i % len(master_key)])) for i, c in enumerate(password))
    return encrypted

def decrypt_password(encrypted_password, master_key):
    """decrypt password using XOR"""
    return ''.join(chr(ord(c) ^ ord(master_key[i % len(master_key)])) for i, c in enumerate(encrypted_password))

# Security questions
SECURITY_QUESTIONS = [
    "您母亲的生日月份是什么？",
    "您出生城市的名称是什么？",
    "您最喜欢的书是什么？",
    "您的小学校名是什么？",
    "您第一个老师的名字是什么？",
    "您最喜欢的电影是什么？",
    "您的座右铭是什么？",
    "您最喜欢的游戏是什么？"
]

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    passwords = PasswordEntry.query.filter_by(user_id=user.id).order_by(PasswordEntry.created_at.desc()).all()
    
    # Count strong passwords (length > 12)
    strong_passwords_count = len([p for p in passwords if len(p.encrypted_password) > 12])
    
    return render_template('dashboard.html', 
                         user=user,
                         passwords=passwords,
                         strong_passwords_count=strong_passwords_count,
                         last_login=datetime.now().strftime('%Y-%m-%d %H:%M'))