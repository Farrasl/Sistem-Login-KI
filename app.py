from flask import Flask, flash, request, session, render_template, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import logging
from datetime import datetime, timedelta
import re
import json
import os
import qrcode
from io import BytesIO
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev_key_change_this_in_production'
JSON_FILE = 'users.json'

# Konfigurasi logging
logging.basicConfig(
    filename='security.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Fungsi untuk membaca data JSON
def read_json():
    if not os.path.exists(JSON_FILE):
        return {}
    try:
        with open(JSON_FILE, 'r') as file:
            return json.load(file)
    except json.JSONDecodeError:
        return {}

# Fungsi untuk menulis data JSON
def write_json(data):
    with open(JSON_FILE, 'w') as file:
        json.dump(data, file, indent=4, default=str)

# Fungsi untuk mendapatkan user berdasarkan username
def get_user(username):
    users = read_json()
    return users.get(username)

# Fungsi untuk menyimpan user baru
def save_user(user_data):
    users = read_json()
    users[user_data['username']] = user_data
    write_json(users)

# Fungsi untuk generaxte QR code
def generate_qr_code(username, totp_secret):
    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(username, issuer_name="MyApp")
    
    # Membuat QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    # Mengubah QR code menjadi image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Mengubah image menjadi base64 string
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()
    
    return qr_code_base64

# Middleware untuk validasi input
def validate_input(data):
    pattern = re.compile(r'^[a-zA-Z0-9_]+$')
    return bool(pattern.match(data))

# Implementasi rate limiting sederhana
def check_rate_limit(user_data):
    failed_attempts = user_data.get('failed_attempts', 0)
    locked_until = user_data.get('locked_until')
    
    if failed_attempts >= 3:
        if locked_until:
            locked_until = datetime.fromisoformat(locked_until)
            if locked_until > datetime.now():
                return False
        user_data['failed_attempts'] = 0
        user_data['locked_until'] = None
        save_user(user_data)
    return True

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not validate_input(username):
            return "Username mengandung karakter yang tidak valid", 400
        
        if len(password) < 8:
            return "Password terlalu pendek", 400
        
        if get_user(username):
            return "Username sudah terdaftar", 400
        
        totp_secret = pyotp.random_base32()
        hashed_password = generate_password_hash(password, method='sha256')
        
        user_data = {
            'username': username,
            'password': hashed_password,
            'totp_secret': totp_secret,
            'failed_attempts': 0,
            'locked_until': None
        }
        
        save_user(user_data)
        logging.info(f"User baru terdaftar: {username}")
        
        # Menyimpan data di session untuk halaman QR code
        session['temp_username'] = username
        session['temp_secret'] = totp_secret
        
        return redirect(url_for('qr_code'))
    
    return render_template('register.html')

@app.route('/qr-code')
def qr_code():
    username = session.get('temp_username')
    totp_secret = session.get('temp_secret')
    
    if not username or not totp_secret:
        return redirect(url_for('register'))
    
    qr_code_base64 = generate_qr_code(username, totp_secret)
    
    # Membersihkan data temporary dari session
    session.pop('temp_username', None)
    session.pop('temp_secret', None)
    
    return render_template('qr_code.html',
                         username=username,
                         totp_secret=totp_secret,
                         qr_code=qr_code_base64)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user_data = get_user(username)
        
        if not user_data:
            flash('Username atau password salah', 'error')
            return redirect(url_for('login'))
        
        if not check_rate_limit(user_data):
            logging.warning(f"Percobaan login yang terkunci untuk user: {username}")
            flash('Akun terkunci karena terlalu banyak percobaan', 'error')
            return redirect(url_for('login'))
        
        if check_password_hash(user_data['password'], password):
            # Jika username dan password benar, redirect ke halaman OTP
            session['temp_login_username'] = username
            return redirect(url_for('otp_verification'))
        
        user_data['failed_attempts'] = user_data.get('failed_attempts', 0) + 1
        if user_data['failed_attempts'] >= 3:
            user_data['locked_until'] = (datetime.now() + timedelta(minutes=15)).isoformat()
        save_user(user_data)
        logging.warning(f"Login gagal untuk user: {username}")
        flash('Username atau password salah', 'error')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/otp', methods=['GET'])
def otp_verification():
    username = session.get('temp_login_username')
    if not username:
        return redirect(url_for('login'))
    return render_template('otp.html', username=username)

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    username = request.form['username']
    totp_code = request.form['totp_code']
    
    user_data = get_user(username)
    if not user_data:
        flash('Sesi telah berakhir', 'error')
        return redirect(url_for('login'))
    
    totp = pyotp.TOTP(user_data['totp_secret'])
    if totp.verify(totp_code):
        session['username'] = username
        session.pop('temp_login_username', None)
        user_data['failed_attempts'] = 0
        save_user(user_data)
        logging.info(f"Login berhasil: {username}")
        return redirect(url_for('dashboard'))
    
    flash('Kode OTP tidak valid', 'error')
    return redirect(url_for('otp_verification'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

if __name__ == '__main__':
    if not os.path.exists(JSON_FILE):
        write_json({})
    app.run(debug=True)