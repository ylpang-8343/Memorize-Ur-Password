from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pyotp
import os
import re
import json
import qrcode
import io
import base64
from cryptography.fernet import Fernet

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Initialize database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    otp_secret = db.Column(db.String(32), nullable=True)
    security_question = db.Column(db.String(200), nullable=False)
    security_answer_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def generate_otp_secret(self):
        self.otp_secret = pyotp.random_base32()
        return self.otp_secret
    
    def get_otp_uri(self):
        return pyotp.totp.TOTP(self.otp_secret).provisioning_uri(
            name=self.username,
            issuer_name="Password Manager"
        )
    
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
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_phone(phone):
    pattern = r'^(\+?60|0)(1[0-9]{8,9}|[2-9][0-9]{7,8})$'
    return re.match(pattern, phone) is not None

def format_malaysia_phone(phone):
    if phone.startswith('0'):
        return '6' + phone
    elif phone.startswith('+60'):
        return phone[1:]
    elif phone.startswith('60'):
        return phone
    else:
        return '60' + phone

def get_encryption_key(user_id):
    key_base = str(user_id) + app.config['SECRET_KEY']
    return base64.urlsafe_b64encode(key_base.ljust(32)[:32].encode())

def encrypt_password(password, user_id):
    fernet = Fernet(get_encryption_key(user_id))
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password, user_id):
    fernet = Fernet(get_encryption_key(user_id))
    return fernet.decrypt(encrypted_password.encode()).decode()

# Template filter
@app.template_filter('decrypt_password')
def decrypt_password_filter(encrypted_password, user_id_str):
    try:
        return decrypt_password(encrypted_password, int(user_id_str))
    except:
        return "解密失败"

@app.template_filter('password_mask')
def password_mask_filter(password):
    if not password:
        return ''
    # Show only first and last character, mask the rest
    if len(password) <= 2:
        return '*' * len(password)
    return password[0] + '*' * (len(password) - 2) + password[-1]

# Security questions
SECURITY_QUESTIONS = [
    "您母亲的生日月份是？",
    "您出生城市的名称是？",
    "您最喜欢的书是？",
    "您的小学校名是？",
    "您第一个老师的名字是？",
    "您最喜欢的电影是？",
    "您的座右铭是？",
    "您最喜欢的歌曲是？"
]

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('identifier')  # username, email, or phone
        
        # Search user by username, email, or phone
        user = User.query.filter(
            (User.username == identifier) | 
            (User.email == identifier) | 
            (User.phone == identifier)
        ).first()
        
        if user:
            # Save user info in session for OTP verification
            session['pending_user_id'] = user.id
            session['pending_username'] = user.username
            
            # Generate and print OTP (in real app, send via email/SMS)
            otp_code = pyotp.TOTP(user.otp_secret).now()
            print(f"DEBUG: OTP for {user.username} is {otp_code}")
            
            flash('验证码已发送到您的邮箱/手机', 'info')
            return redirect(url_for('otp_verification'))
        else:
            flash('用户不存在，请先注册', 'error')
            return redirect(url_for('register'))
    
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        security_question = request.form.get('security_question')
        security_answer = request.form.get('security_answer')
        
        # Validate input
        if not username or not email or not security_question or not security_answer:
            flash('所有字段均为必填项', 'error')
            return render_template('auth/register.html', security_questions=SECURITY_QUESTIONS)
        
        if not is_valid_email(email):
            flash('请输入有效的邮箱地址', 'error')
            return render_template('auth/register.html', security_questions=SECURITY_QUESTIONS)
        
        if phone:
            if not is_valid_phone(phone):
                flash('请输入有效的马来西亚手机号码', 'error')
                return render_template('auth/register.html', security_questions=SECURITY_QUESTIONS)
            phone = format_malaysia_phone(phone)
        
        # Check for existing user
        if User.query.filter_by(username=username).first():
            flash('用户名已存在', 'error')
            return render_template('auth/register.html', security_questions=SECURITY_QUESTIONS)
        
        if User.query.filter_by(email=email).first():
            flash('邮箱已存在', 'error')
            return render_template('auth/register.html', security_questions=SECURITY_QUESTIONS)
        
        if phone and User.query.filter_by(phone=phone).first():
            flash('手机号已存在', 'error')
            return render_template('auth/register.html', security_questions=SECURITY_QUESTIONS)
        
        # Create new user
        user = User(
            username=username, 
            email=email, 
            phone=phone,
            security_question=security_question
        )
        user.generate_otp_secret()
        user.set_security_answer(security_answer)
        
        db.session.add(user)
        db.session.commit()
        
        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/register.html', security_questions=SECURITY_QUESTIONS)

@app.route('/otp-verification', methods=['GET', 'POST'])
def otp_verification():
    # Check for pending user in session
    if 'pending_user_id' not in session:
        flash('请先登录', 'error')
        return redirect(url_for('login'))
    
    user_id = session['pending_user_id']
    user = User.query.get(user_id)
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        
        if user.verify_otp(otp):
            # OTP verified, proceed to security question
            session['otp_verified'] = True
            flash('OTP验证成功，请回答安全问题', 'success')
            return redirect(url_for('security_question'))
        else:
            flash('验证码错误，请重新输入', 'error')
    
    # Show OTP directly in development mode
    development_otp = pyotp.TOTP(user.otp_secret).now() if app.debug else None
    
    return render_template('auth/otp.html', development_otp=development_otp)

@app.route('/resend-otp')
def resend_otp():
    if 'pending_user_id' not in session:
        flash('请先登录', 'error')
        return redirect(url_for('login'))
    
    user_id = session['pending_user_id']
    user = User.query.get(user_id)
    
    # regenerate and print OTP
    otp_code = pyotp.TOTP(user.otp_secret).now()
    print(f"DEBUG: 重新发送的OTP for {user.username} is {otp_code}")
    
    flash('验证码已重新发送', 'info')
    return redirect(url_for('otp_verification'))

@app.route('/security-question', methods=['GET', 'POST'])
def security_question():
    # Check for pending user and OTP verification
    if 'pending_user_id' not in session or not session.get('otp_verified'):
        flash('请先完成OTP验证', 'error')
        return redirect(url_for('login'))
    
    user_id = session['pending_user_id']
    user = User.query.get(user_id)
    
    if request.method == 'POST':
        answer = request.form.get('answer')
        
        if user.check_security_answer(answer):
            # Security answer correct, log in user
            session['user_id'] = user.id
            session['username'] = user.username
            session.pop('pending_user_id', None)
            session.pop('pending_username', None)
            session.pop('otp_verified', None)
            
            flash('登录成功', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('安全问题答案错误', 'error')
    
    return render_template('auth/security_question.html', question=user.security_question)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    passwords = PasswordEntry.query.filter_by(user_id=user.id).order_by(PasswordEntry.created_at.desc()).all()
    
    # Count strong passwords (length > 12)
    strong_passwords_count = 0
    for p in passwords:
        try:
            decrypted = decrypt_password(p.encrypted_password, user.id)
            if len(decrypted) >= 12:
                strong_passwords_count += 1
        except:
            pass
    
    return render_template('main/dashboard.html', 
                         user=user,
                         passwords=passwords,
                         strong_passwords_count=strong_passwords_count,
                         last_login=datetime.now().strftime('%Y-%m-%d %H:%M'))

@app.route('/add-password', methods=['GET', 'POST'])
def add_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        platform = request.form.get('platform')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        notes = request.form.get('notes')
        
        # Form validation
        if not platform or not username or not password:
            flash('请填写所有必填字段', 'error')
            return render_template('main/add_password.html')
        
        if password != confirm_password:
            flash('两次输入的密码不一致', 'error')
            return render_template('main/add_password.html')
        
        # Encrypt password
        encrypted_password = encrypt_password(password, session['user_id'])
        
        new_entry = PasswordEntry(
            platform=platform,
            username=username,
            encrypted_password=encrypted_password,
            notes=notes,
            user_id=session['user_id']
        )
        
        db.session.add(new_entry)
        db.session.commit()
        
        flash('密码保存成功', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('main/add_password.html')

@app.route('/find-password')
def find_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    search_query = request.args.get('q', '')
    sort_by = request.args.get('sort', 'newest')
    show_passwords = request.args.get('show_passwords') == 'on'
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Build query
    query = PasswordEntry.query.filter_by(user_id=user.id)
    
    if search_query:
        query = query.filter(
            (PasswordEntry.platform.ilike(f'%{search_query}%')) |
            (PasswordEntry.username.ilike(f'%{search_query}%')) |
            (PasswordEntry.notes.ilike(f'%{search_query}%'))
        )
    
    # Sorting
    if sort_by == 'oldest':
        query = query.order_by(PasswordEntry.created_at.asc())
    elif sort_by == 'platform':
        query = query.order_by(PasswordEntry.platform.asc())
    else:  # newest
        query = query.order_by(PasswordEntry.created_at.desc())
    
    # Pagination
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    passwords = pagination.items
    
    return render_template('main/find_password.html',
                         passwords=passwords,
                         search_query=search_query,
                         sort_by=sort_by,
                         show_passwords=show_passwords,
                         page=page,
                         total_pages=pagination.pages)

@app.route('/edit-password/<int:password_id>', methods=['GET', 'POST'])
def edit_password(password_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    entry = PasswordEntry.query.filter_by(id=password_id, user_id=session['user_id']).first()
    if not entry:
        flash('密码记录不存在', 'error')
        return redirect(url_for('find_password'))
    if request.method == 'POST':
        entry.platform = request.form.get('platform')
        entry.username = request.form.get('username')
        password = request.form.get('password')
        if password:
            entry.encrypted_password = encrypt_password(password, session['user_id'])
        entry.notes = request.form.get('notes')
        db.session.commit()
        flash('密码已更新', 'success')
        return redirect(url_for('find_password'))
    return render_template('main/edit_password.html', password=entry)

@app.route('/view-password/<int:password_id>')
def view_password(password_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    entry = PasswordEntry.query.filter_by(id=password_id, user_id=session['user_id']).first()
    if not entry:
        flash('密码记录不存在', 'error')
        return redirect(url_for('find_password'))
    
    # decrypt password for viewing
    decrypted_password = decrypt_password(entry.encrypted_password, session['user_id'])
    
    return render_template('main/view_password.html', 
                         password=entry,
                         decrypted_password=decrypted_password)

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    preferences = session.get('preferences', {
        'auto_lock': True,
        'show_passwords': False,
        'backup_reminder': True,
        'theme': 'light'
    })
    # Provide backup info for the backup tab
    backup_files = []
    backup_dir = 'backups'
    if os.path.exists(backup_dir):
        for fname in os.listdir(backup_dir):
            fpath = os.path.join(backup_dir, fname)
            if os.path.isfile(fpath):
                stat = os.stat(fpath)
                backup_files.append({
                    'name': fname,
                    'size': f"{stat.st_size // 1024} KB",
                    'date': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
                })
    backup_count = len(backup_files)
    last_backup = backup_files[-1]['date'] if backup_files else None

    return render_template(
        'main/settings.html',
        user=user,
        preferences=preferences,
        backup_files=backup_files,
        backup_count=backup_count,
        last_backup=last_backup
    )

@app.route('/generate-qr-code')
def generate_qr_code():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(user.get_otp_uri())
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    return send_file(img_io, mimetype='image/png')

@app.route('/update-profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        flash('请先登录', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    email = request.form.get('email')
    phone = request.form.get('phone')
    
    # check if AJAX request
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    try:
        if email and email != user.email:
            if User.query.filter_by(email=email).first():
                if is_ajax:
                    return jsonify(success=False, message="邮箱已存在")
                else:
                    flash('邮箱已存在', 'error')
                    return redirect(url_for('settings'))
            user.email = email
        
        if phone and phone != user.phone:
            if not is_valid_phone(phone):
                if is_ajax:
                    return jsonify(success=False, message="无效的手机号码")
                else:
                    flash('无效的手机号码', 'error')
                    return redirect(url_for('settings'))
            formatted_phone = format_malaysia_phone(phone)
            if User.query.filter_by(phone=formatted_phone).first():
                if is_ajax:
                    return jsonify(success=False, message="手机号已存在")
                else:
                    flash('手机号已存在', 'error')
                    return redirect(url_for('settings'))
            user.phone = formatted_phone
        
        db.session.commit()
        
        if is_ajax:
            return jsonify(success=True, message="个人信息更新成功")
        else:
            flash('个人信息更新成功', 'success')
            return redirect(url_for('settings'))
    
    except Exception as e:
        if is_ajax:
            return jsonify(success=False, message=f"更新失败: {str(e)}")
        else:
            flash(f'更新失败: {str(e)}', 'error')
            return redirect(url_for('settings'))

@app.route('/update-preferences', methods=['POST'])
def update_preferences():
    if 'user_id' not in session:
        return jsonify(success=False, message="未登录")
    
    try:
        # get preferences from form
        auto_lock = request.form.get('auto_lock') == 'on'
        show_passwords = request.form.get('show_passwords') == 'on'
        backup_reminder = request.form.get('backup_reminder') == 'on'
        theme = request.form.get('theme', 'light')
        
        # save to session
        session['preferences'] = {
            'auto_lock': auto_lock,
            'show_passwords': show_passwords,
            'backup_reminder': backup_reminder,
            'theme': theme
        }
        
        # set session to be permanent
        session.permanent = True
        
        # if AJAX request, return JSON
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(success=True, message="偏好设置已保存")
        
        flash('偏好设置已保存', 'success')
        return redirect(url_for('settings'))
        
    except Exception as e:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(success=False, message=f'保存失败: {str(e)}')
        
        flash(f'保存失败: {str(e)}', 'error')
        return redirect(url_for('settings'))

@app.route('/update-security-question', methods=['POST'])
def update_security_question():
    if 'user_id' not in session:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(success=False, message="未登录")
        else:
            flash('请先登录', 'error')
            return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    security_question = request.form.get('security_question')
    security_answer = request.form.get('security_answer')
    confirm_security_answer = request.form.get('confirm_security_answer')
    
    # check if AJAX request
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    if not security_question or not security_answer or not confirm_security_answer:
        if is_ajax:
            return jsonify(success=False, message="请填写所有字段")
        else:
            flash('请填写所有字段', 'error')
            return redirect(url_for('settings'))
    
    if security_answer != confirm_security_answer:
        if is_ajax:
            return jsonify(success=False, message="两次输入的答案不一致")
        else:
            flash('两次输入的答案不一致', 'error')
            return redirect(url_for('settings'))
    
    user.security_question = security_question
    user.set_security_answer(security_answer)
    
    db.session.commit()
    
    if is_ajax:
        return jsonify(success=True, message="安全问题更新成功")
    else:
        flash('安全问题更新成功', 'success')
        return redirect(url_for('settings'))

@app.route('/toggle-otp', methods=['POST'])
def toggle_otp():
    if 'user_id' not in session:
        return jsonify(success=False, message="未登录")
    
    user = User.query.get(session['user_id'])
    
    if user.otp_secret:
        # Disable OTP
        user.otp_secret = None
        message = "双重验证已禁用"
    else:
        # Enable OTP
        user.generate_otp_secret()
        message = "双重验证已启用"
    
    db.session.commit()
    return jsonify(success=True, message=message)

@app.route('/delete-password/<int:password_id>', methods=['POST', 'DELETE'])
def delete_password(password_id):
    if 'user_id' not in session:
        return jsonify(success=False, message="未登录")
    entry = PasswordEntry.query.filter_by(id=password_id, user_id=session['user_id']).first()
    if not entry:
        return jsonify(success=False, message="密码记录不存在")
    db.session.delete(entry)
    db.session.commit()
    return jsonify(success=True, message="密码删除成功")

@app.route('/delete-all-passwords', methods=['DELETE'])
def delete_all_passwords():
    if 'user_id' not in session:
        return jsonify(success=False, message="未登录")
    
    PasswordEntry.query.filter_by(user_id=session['user_id']).delete()
    db.session.commit()
    return jsonify(success=True, message="所有密码已删除")

@app.route('/delete-account', methods=['DELETE'])
def delete_account():
    if 'user_id' not in session:
        return jsonify(success=False, message="未登录")
    
    try:
        # Delete all passwords first
        PasswordEntry.query.filter_by(user_id=session['user_id']).delete()
        
        # Delete user account
        user = User.query.get(session['user_id'])
        if user:
            db.session.delete(user)
            db.session.commit()
            
            session.clear()
            return jsonify(success=True, message="账户已注销")
        else:
            return jsonify(success=False, message="用户不存在")
            
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=f"注销失败: {str(e)}")

@app.route('/logout-other-devices', methods=['POST'])
def logout_other_devices():
    if 'user_id' not in session:
        return jsonify(success=False, message="未登录")
    
    return jsonify(success=True, message="其他设备已退出登录")

@app.route('/backup', methods=['POST'])
def backup():
    if 'user_id' not in session:
        return jsonify(success=False, message="未登录")
    
    user = User.query.get(session['user_id'])
    passwords = PasswordEntry.query.filter_by(user_id=user.id).all()
    
    # Create backup data
    backup_data = {
        'user': {
            'username': user.username,
            'email': user.email,
            'phone': user.phone
        },
        'passwords': [
            {
                'platform': p.platform,
                'username': p.username,
                'password': decrypt_password(p.encrypted_password, user.id),
                'notes': p.notes,
                'created_at': p.created_at.isoformat()
            } for p in passwords
        ],
        'backup_date': datetime.now().isoformat(),
        'backup_version': '1.0'
    }
    
    # Save backup file
    filename = f'backup_{user.username}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    filepath = os.path.join('backups', filename)
    os.makedirs('backups', exist_ok=True)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(backup_data, f, ensure_ascii=False, indent=2)
    
    download_url = url_for('download_backup', filename=filename)
    return jsonify(success=True, download_url=download_url)

@app.route('/download-backup/<filename>')
def download_backup(filename):
    return send_file(os.path.join('backups', filename), as_attachment=True)

@app.route('/restore', methods=['POST'])
def restore():
    if 'user_id' not in session:
        return jsonify(success=False, message="未登录")
    
    if 'file' not in request.files:
        return jsonify(success=False, message="请选择备份文件")
    
    file = request.files['file']
    if file.filename == '':
        return jsonify(success=False, message="请选择有效的备份文件")
    
    try:
        backup_data = json.load(file.stream)
        
        # Restore passwords
        for pwd_data in backup_data.get('passwords', []):
            encrypted_password = encrypt_password(pwd_data['password'], session['user_id'])
            
            new_entry = PasswordEntry(
                platform=pwd_data['platform'],
                username=pwd_data['username'],
                encrypted_password=encrypted_password,
                notes=pwd_data.get('notes', ''),
                user_id=session['user_id']
            )
            db.session.add(new_entry)
        
        db.session.commit()
        return jsonify(success=True, message="数据恢复成功")
    
    except Exception as e:
        return jsonify(success=False, message=f"恢复失败: {str(e)}")

@app.route('/export', methods=['POST'])
def export():
    if 'user_id' not in session:
        return jsonify(success=False, message="未登录")
    
    user = User.query.get(session['user_id'])
    passwords = PasswordEntry.query.filter_by(user_id=user.id).all()
    
    format_type = request.json.get('format', 'json')
    
    if format_type == 'csv':
        # CSV format
        csv_data = "平台,用户名,密码,备注\n"
        for p in passwords:
            decrypted = decrypt_password(p.encrypted_password, user.id)
            csv_data += f'"{p.platform}","{p.username}","{decrypted}","{p.notes or ""}"\n'
        
        filename = f'export_{user.username}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        filepath = os.path.join('exports', filename)
        os.makedirs('exports', exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(csv_data)
    
    else:
        # JSON format (default)
        export_data = {
            'passwords': [
                {
                    'platform': p.platform,
                    'username': p.username,
                    'password': decrypt_password(p.encrypted_password, user.id),
                    'notes': p.notes,
                    'created_at': p.created_at.isoformat()
                } for p in passwords
            ],
            'export_date': datetime.now().isoformat()
        }
        
        filename = f'export_{user.username}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        filepath = os.path.join('exports', filename)
        os.makedirs('exports', exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)
    
    download_url = url_for('download_export', filename=filename)
    return jsonify(success=True, download_url=download_url)

@app.route('/download-export/<filename>')
def download_export(filename):
    return send_file(os.path.join('exports', filename), as_attachment=True)

@app.route('/logout')
def logout():
    session.clear()
    flash('您已成功退出登录', 'success')
    return redirect(url_for('index'))

# Initialize database
def init_db():
    with app.app_context():
        db.create_all()
        # Create backup and export directories
        os.makedirs('backups', exist_ok=True)
        os.makedirs('exports', exist_ok=True)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)