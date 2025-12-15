from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from models import db, Student, Book, Transaction, Settings, User, LoginRequest, QRLoginRequest
from datetime import datetime, timedelta
from xhtml2pdf import pisa
from io import BytesIO
from sqlalchemy import or_, func, desc
from sqlalchemy.orm import joinedload
from flask_wtf.csrf import CSRFProtect
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from guvenlik import guardian # Import Security Guardian
from book_api import get_book_details # Import Book API Helper


app = Flask(__name__)

# CONFIGURATION FOR EXE & PERSISTENCE
import sys, os, webbrowser
from threading import Timer

if getattr(sys, 'frozen', False):
    # If running as EXE, use the folder where .exe is located
    application_path = os.path.dirname(sys.executable)
    # Turn off debug in production EXE
    DEBUG_MODE = False
else:
    # If running as script, use the current directory
    application_path = os.path.dirname(os.path.abspath(__file__))
    DEBUG_MODE = True

# Persistent DB path (next to the EXE)
db_name = 'library.db'
db_path = os.path.join(application_path, db_name)

from dotenv import load_dotenv
load_dotenv()

# Use Supabase URL if available, otherwise fallback to SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL') or f'sqlite:///{db_path}'

# Register custom font family for PDF
try:
    font_dir = os.path.join(application_path, 'static', 'fonts')
    
    # Define font files
    fonts = {
        'TurkishFont': 'arial.ttf',
        'TurkishFont-Bold': 'arialbd.ttf',
        'TurkishFont-Italic': 'ariali.ttf',
        'TurkishFont-BoldItalic': 'arialbi.ttf'
    }
    
    # Register each font
    for name, filename in fonts.items():
        font_path = os.path.join(font_dir, filename)
        if os.path.exists(font_path):
            pdfmetrics.registerFont(TTFont(name, font_path))
            print(f"Registered {name} from {font_path}")
        else:
            print(f"Font not found: {font_path}")
            
    # Register font family
    from reportlab.pdfbase.pdfmetrics import registerFontFamily
    registerFontFamily('TurkishFont', normal='TurkishFont', bold='TurkishFont-Bold', italic='TurkishFont-Italic', boldItalic='TurkishFont-BoldItalic')
    print("Registered TurkishFont family")
    
except Exception as e:
    print(f"Error registering font family: {e}")

app.config['SECRET_KEY'] = 'cok_gizli_ve_guclu_bir_anahtar_12345'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db.init_app(app)
guardian.init_app(app) # Initialize Firewall
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = 'strong' # Protect against session hijacking (IP/User-Agent check)

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user:
        # STRICT SESSION SECURITY (IP Binding)
        # If the stored login IP is different from the current IP, we consider it a potential hijack.
        # However, we must be careful with mobile users switching from WiFi to 4G.
        # But per user request "permanent ban if doing this", we will be strict.
        
        # We use a helper from guardian to check if the session fingerprint matches
        # Actually, we can just check stored last_login_ip vs current remote_addr
        if user.last_login_ip and user.last_login_ip != request.remote_addr:
            # Check if this might be a valid device switch (in allowed_devices)
            # But duplicate session cookie usage implies SAME session token on NEW IP.
            # If session token is same, but IP changed -> Hijack or Network Switch.
            # If user explicitly said "ban", we treat as Hijack for now or log threat.
            
            # Let's verify via Guardian
            is_valid, reason = guardian.fingerprint.check_integrity(session)
            if not is_valid:
                 # Trigger Ban via Guardian
                 guardian.punish_hijacker(request.remote_addr, f"Session Hijack: {reason}")
                 return None
                 
    return user

csp = {
    'default-src': '\'self\'',
    'script-src': [
        '\'self\'',
        '\'unsafe-inline\'', # Required for some inline scripts
        'https://cdnjs.cloudflare.com', # FontAwesome, html2pdf
        'https://raw.githack.com',
        'https://cdn.jsdelivr.net', # JsBarcode, FullCalendar
        'https://unpkg.com' # Backup for some libs
    ],
    'style-src': [
        '\'self\'',
        '\'unsafe-inline\'',
        'https://cdnjs.cloudflare.com',
        'https://fonts.googleapis.com'
    ],
    'font-src': [
        '\'self\'',
        'https://cdnjs.cloudflare.com',
        'https://fonts.gstatic.com'
    ],
    'img-src': ['\'self\'', 'data:', '*'] # Allow images from anywhere for now (covers external URLs)
}

talisman = Talisman(app, content_security_policy=csp, force_https=False) # force_https=False for local dev

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["50000 per day", "4000 per hour"],
    storage_uri="memory://"
)

@app.context_processor
def inject_settings():
    settings = Settings.query.first()
    if not settings:
        settings = Settings(loan_period=15, school_name='Kütüphane Otomasyonu')
        db.session.add(settings)
        db.session.commit()
    
    # Create default admin if not exists
    if not User.query.first():
        hashed_password = generate_password_hash('admin123')
        default_user = User(username='admin', password_hash=hashed_password)
        db.session.add(default_user)
        db.session.commit()

    return dict(settings=settings, now=datetime.utcnow())



import json
import uuid
import random
import string
from datetime import timedelta
from models import LoginRequest

def get_device_fingerprint():
    # Basic fingerprint: User-Agent + IP (Enhanced in frontend)
    ua = request.headers.get('User-Agent', '')
    ip = request.remote_addr
    return f"{ua}|{ip}"

def is_device_allowed(user, req_token):
    try:
        allowed = json.loads(user.allowed_devices)
        return req_token in allowed
    except:
        return False

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            # 2FA / DEVICE CHECK LOGIC
            
            # 1. Device Token (from cookie)
            client_token = request.cookies.get('device_token')
            if not client_token:
                client_token = str(uuid.uuid4()) # New device candidate
            
            # 2. Check if device is allowed
            if is_device_allowed(user, client_token):
                # Device is known -> Login directly
                login_user(user)
                user.session_token = str(uuid.uuid4()) # Session Lockdown Token
                user.last_login_ip = request.remote_addr
                user.last_activity = datetime.utcnow()
                db.session.commit()
                
                session['user_session_token'] = user.session_token
                
                resp = redirect(url_for('index'))
                resp.set_cookie('device_token', client_token, max_age=31536000) # 1 Year
                return resp
            
            else:
                # Device is UNKNOWN
                
                # Check for ACTIVE session elsewhere (to decide if we need approval)
                is_session_active = False
                if user.session_token and user.last_activity:
                    # Consider active if activity within last 5 minutes
                    if (datetime.utcnow() - user.last_activity).total_seconds() < 300:
                        is_session_active = True
                
                # If NO active session is found OR usage is DISABLED by user, we TRUST this new device immediately.
                # This solves the "locked out" issue if you are the first one logging in.
                if not is_session_active or not getattr(user, 'device_verification_enabled', True):
                    # Auto-Register Device
                    try:
                        allowed = json.loads(user.allowed_devices)
                    except:
                        allowed = []
                    allowed.append(client_token)
                    user.allowed_devices = json.dumps(allowed)
                    
                    # Login
                    login_user(user)
                    user.session_token = str(uuid.uuid4())
                    user.last_login_ip = request.remote_addr
                    user.last_activity = datetime.utcnow()
                    db.session.commit()
                    
                    session['user_session_token'] = user.session_token
                    
                    resp = redirect(url_for('index'))
                    resp.set_cookie('device_token', client_token, max_age=31536000) # 1 Year
                    return resp
                
                # If there IS an active session, force 2FA (Device A must approve Device B)
                
                # CLEANUP: Remove any existing pending requests for this token to avoid UniqueViolation
                existing_req = LoginRequest.query.filter_by(request_token=client_token).first()
                if existing_req:
                    db.session.delete(existing_req)
                    db.session.commit()

                # Create Login Request
                verification_code = ''.join(random.choices(string.digits, k=6))
                new_request = LoginRequest(
                    user_id=user.id,
                    request_token=client_token,
                    verification_code=verification_code,
                    ip_address=request.remote_addr,
                    device_info=request.headers.get('User-Agent'),
                    expires_at=datetime.utcnow() + timedelta(minutes=2)
                )
                db.session.add(new_request)
                db.session.commit()
                
                # Redirect to verification waiting page
                return render_template('verify_2fa.html', request_id=new_request.id, client_token=client_token)

        else:
            flash('Giriş başarısız. Lütfen bilgilerinizi kontrol edin.', 'danger')
            
    return render_template('login.html')

@app.route('/api/2fa/check-requests')
@login_required
def check_2fa_requests():
    # Called by ACTIVE SESSIONS (Cihaz A) to see if anyone is trying to login
    # Only pending requests that are not expired
    req = LoginRequest.query.filter_by(user_id=current_user.id, status='pending')\
            .filter(LoginRequest.expires_at > datetime.utcnow())\
            .order_by(LoginRequest.created_at.desc()).first()
            
    if req:
        return jsonify({
            'found': True,
            'code': req.verification_code,
            'ip': req.ip_address,
            'device': req.device_info[:50] + '...',
            'request_id': req.id
        })
    return jsonify({'found': False})

@app.route('/api/2fa/action/<int:request_id>/<action>', methods=['POST'])
@login_required
def action_2fa_request(request_id, action):
    # Action: approve (not used directly here, done via code), reject
    req = LoginRequest.query.get_or_404(request_id)
    if req.user_id != current_user.id:
        return jsonify({'success': False}), 403
        
    if action == 'reject':
        req.status = 'rejected'
        db.session.commit()
        return jsonify({'success': True})
        
    return jsonify({'success': False})

@app.route('/verify-2fa-status/<int:request_id>')
def verify_2fa_status(request_id):
    # Polling for the WAITING DEVICE (Cihaz B)
    req = LoginRequest.query.get(request_id)
    if not req:
        return jsonify({'status': 'expired'})
    
    if req.status == 'approved':
        return jsonify({'status': 'approved'})
    elif req.status == 'rejected':
        return jsonify({'status': 'rejected'})
    elif datetime.utcnow() > req.expires_at:
        return jsonify({'status': 'expired'})
        
    return jsonify({'status': 'pending'})

@app.route('/submit-2fa-code', methods=['POST'])
@csrf.exempt
def submit_2fa_code():
    # Submitting the code from Cihaz B (or theoretically Cihaz A could autofill)
    # Actually, Cihaz A displays code, Cihaz B Enters it.
    
    print("DEBUG: 2FA Submission Received")
    print(f"DEBUG: Form Data: {request.form}")
    
    req_id = request.form.get('request_id')
    code = request.form.get('code')
    
    if code:
        code = code.strip()
        
    if not req_id:
        print("DEBUG: Missing request_id")
        return jsonify({'success': False, 'message': 'İstek ID eksik.'})
        
    try:
        req_id = int(req_id)
    except:
        print(f"DEBUG: Invalid request_id format: {req_id}")
        return jsonify({'success': False, 'message': 'Geçersiz İstek ID.'})
    
    req = LoginRequest.query.get(req_id)
    if not req:
         return jsonify({'success': False, 'message': 'İstek bulunamadı.'})
         
    if req.status == 'approved':
        # Already approved (likely double submit or race condition)
        # Just return success to let the user in.
        return jsonify({'success': True, 'redirect': url_for('index')})
        
    if req.status != 'pending':
         return jsonify({'success': False, 'message': 'İstek süresi dolmuş veya reddedilmiş.'})
         
    if req.verification_code == code:
        # SUCCESS!
        req.status = 'approved'
        user = User.query.get(req.user_id)
        
        # Add to allowed devices
        try:
            allowed = json.loads(user.allowed_devices)
        except:
            allowed = []
        allowed.append(req.request_token)
        user.allowed_devices = json.dumps(allowed)
        
        # Login
        login_user(user)
        user.session_token = str(uuid.uuid4())
        db.session.commit()
        session['user_session_token'] = user.session_token
        
        resp = jsonify({'success': True, 'redirect': url_for('index')})
        resp.set_cookie('device_token', req.request_token, max_age=31536000)
        return resp
    else:
        return jsonify({'success': False, 'message': 'Hatalı Kod!'})

@app.route('/api/qr/generate')
def generate_qr():
    # Generate unique token for QR
    token = str(uuid.uuid4())
    new_qr = QRLoginRequest(
        token=token,
        expires_at=datetime.utcnow() + timedelta(minutes=2)
    )
    db.session.add(new_qr)
    db.session.commit()
    return jsonify({'token': token, 'expires_in': 120})

@app.route('/api/qr/status/<token>')
def check_qr_status(token):
    qr_req = QRLoginRequest.query.filter_by(token=token).first()
    if not qr_req:
        return jsonify({'status': 'invalid'})
    
    if datetime.utcnow() > qr_req.expires_at:
        return jsonify({'status': 'expired'})
        
    if qr_req.status == 'approved':
        # Perform Login for the waiting Desktop Client
        user = User.query.get(qr_req.user_id)
        if user:
            login_user(user)
            user.session_token = str(uuid.uuid4())
            user.last_login_ip = request.headers.get('X-Forwarded-For', request.remote_addr) # Best effort IP
            user.last_activity = datetime.utcnow()
            db.session.commit()
            
            session['user_session_token'] = user.session_token
            
            # Auto-trust this device? Maybe not for QR login, let's keep it safe. 
            # Or yes, if they scanned it, they trust it.
            # Let's add a device token if missing
            
            resp = jsonify({'status': 'approved', 'redirect': url_for('index')})
            # Generate a new device token for this desktop if it doesn't have one
            # The desktop JS will handle the cookie set if we return it? 
            # Actually, server sets cookie on response... BUT this response goes to Desktop polling!
            # So yes, we can set the cookie here.
            client_token = request.cookies.get('device_token')
            if not client_token:
                 client_token = str(uuid.uuid4())
                 resp.set_cookie('device_token', client_token, max_age=31536000)
                 
                 # Trust this new device since it was approved by a trusted mobile
                 try:
                    allowed = json.loads(user.allowed_devices)
                 except:
                    allowed = []
                 allowed.append(client_token)
                 user.allowed_devices = json.dumps(allowed)
                 db.session.commit()
            
            # Mark token as used/consumed so it can't be used again
            qr_req.status = 'consumed' 
            db.session.commit()
            
            return resp
            
    return jsonify({'status': qr_req.status})

@app.route('/api/qr/approve', methods=['POST'])
@login_required # MUST be logged in on mobile
@csrf.exempt # API call from mobile JS
def approve_qr_login():
    data = request.json
    token = data.get('token')
    
    qr_req = QRLoginRequest.query.filter_by(token=token).first()
    if not qr_req:
        return jsonify({'success': False, 'message': 'Geçersiz QR Kodu'})
        
    if datetime.utcnow() > qr_req.expires_at:
        return jsonify({'success': False, 'message': 'QR Kodu süresi dolmuş'})
        
    qr_req.status = 'approved'
    qr_req.user_id = current_user.id
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Giriş Onaylandı'})

@app.before_request
def security_check():
    # 1. Session Lockdown Check
    if current_user.is_authenticated:
        if 'user_session_token' in session:
            # Check if token matches DB
            # MULTI-SESSION SUPPORT: Disabled this check to allow multiple devices
            # if session['user_session_token'] != current_user.session_token:
            #     logout_user()
            #     flash('Oturumunuz başka bir cihazda açıldığı için sonlandırıldı.', 'warning')
            #     return redirect(url_for('login'))
            pass
                
    # 2. Watcher Time Check (Existing logic moved here or kept same)

def check_concurrent_watcher():
    if current_user.is_authenticated and getattr(current_user, 'role', '') == 'watcher':
        settings = Settings.query.first()
        if settings and settings.active_watcher_id and settings.active_watcher_id != current_user.id:
            logout_user()
            flash('Başka bir nöbetçi giriş yaptığı için oturumunuz sonlandırıldı.', 'warning')
            return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    # Clear active watcher if it's the current user
    if getattr(current_user, 'role', '') == 'watcher':
        settings = Settings.query.first()
        if settings and settings.active_watcher_id == current_user.id:
            settings.active_watcher_id = None
            db.session.commit()

    session.pop('watcher_restricted_student', None)
    logout_user()
    return redirect(url_for('login'))

@app.route('/hesap-olustur', methods=['GET', 'POST'])
@login_required 
def register():
    # SUPER ADMIN CHECK (Security)
    if current_user.username != 'admin':
        flash('Yetkisiz işlem! Sadece Süper Admin yeni hesap oluşturabilir.', 'danger')
        return redirect(url_for('settings'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check existing
        if User.query.filter_by(username=username).first():
            flash('Bu kullanıcı adı zaten kullanılıyor!', 'danger')
            return redirect(url_for('register'))
            
        new_user = User(username=username, role='admin') # Teacher has full access
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'{username} adında YENİ ÖĞRETMEN hesabı başarıyla oluşturuldu!', 'success')
        return redirect(url_for('settings'))
        
    return render_template('register.html')

@app.route('/nobetci-olustur', methods=['GET', 'POST'])
@login_required
def create_watcher():
    # SUPER ADMIN CHECK
    if current_user.username != 'admin':
        flash('Yetkisiz işlem! Sadece Süper Admin nöbetçi hesabı oluşturabilir.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Bu kullanıcı adı zaten kullanılıyor!', 'danger')
            return redirect(url_for('create_watcher'))
            
        # Create user with 'watcher' role
        new_user = User(username=username, role='watcher')
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'{username} adında NÖBETÇİ ÖĞRENCİ hesabı oluşturuldu.', 'warning')
        return redirect(url_for('index'))

    return render_template('create_watcher.html')

@app.route('/api/watcher/set-restriction', methods=['POST'])
@login_required
def set_watcher_restriction():
    if getattr(current_user, 'role', 'admin') != 'watcher':
         return jsonify({'success': False, 'message': 'Only watchers.'}), 403
         
    data = request.get_json()
    student_key = data.get('student_number')
    
    if not student_key:
        return jsonify({'success': False, 'message': 'Gerekli alan eksik.'}), 400
        
    from flask import session
    session['watcher_restricted_student'] = str(student_key).strip()
    return jsonify({'success': True})

@app.route('/')
@login_required
def index():
    total_students = Student.query.count()
    total_books = Book.query.count()
    active_loans = Transaction.query.filter_by(status='active').count()
    recent_transactions = Transaction.query.order_by(Transaction.issue_date.desc()).limit(5).all()
    overdue_query = Transaction.query.filter(Transaction.status == 'active', Transaction.due_date < datetime.utcnow())
    overdue_loans_count = overdue_query.count()
    overdue_loans = overdue_query.order_by(Transaction.due_date).limit(20).all()
    
    stats = {
        'total_students': total_students,
        'total_books': total_books,
        'active_loans': active_loans,
        'overdue_loans': overdue_loans_count
    }
    
    return render_template('dashboard.html', 
                         stats=stats, 
                         recent_transactions=recent_transactions,
                         overdue_loans=overdue_loans)

@app.route('/students')
@login_required
def students():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search_query = request.args.get('search', '')
    
    query = Student.query
    
    if search_query:
        query = query.filter(
            or_(
                Student.name.contains(search_query),
                Student.surname.contains(search_query),
                Student.school_number.contains(search_query)
            )
        )
    
    # Pagination
    students_pagination = query.order_by(Student.name).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('students.html', students=students_pagination, search_query=search_query)

@app.route('/student/<int:id>')
@login_required
def student_detail(id):
    student = Student.query.options(joinedload(Student.transactions).joinedload(Transaction.book)).get_or_404(id)
    history = Transaction.query.options(joinedload(Transaction.book)).filter_by(student_id=id).order_by(Transaction.issue_date.desc()).all()
    return render_template('student_detail.html', student=student, history=history)

@app.route('/students/add', methods=['GET', 'POST'])
@login_required
def add_student():
    if request.method == 'POST':
        name = request.form['name']
        surname = request.form['surname']
        school_number = request.form['school_number']
        class_name = request.form['class_name']
        email = request.form.get('email')
        phone = request.form.get('phone')
        address = request.form.get('address')
        
        # Check if student already exists
        existing_student = Student.query.filter_by(school_number=school_number).first()
        if existing_student:
             flash(f'Hata: {school_number} numaralı öğrenci ({existing_student.name} {existing_student.surname}) zaten kayıtlı!', 'danger')
             return render_template('add_student.html', 
                                    name=name, surname=surname, school_number=school_number, 
                                    class_name=class_name, email=email, phone=phone, address=address)

        new_student = Student(name=name, surname=surname, school_number=school_number, class_name=class_name, email=email, phone=phone, address=address)
        
        try:
            db.session.add(new_student)
            db.session.commit()
            flash('Öğrenci başarıyla eklendi!', 'success')
            
            next_page = request.args.get('next')
            if next_page == 'index':
                return redirect(url_for('index'))
            return redirect(url_for('students'))
        except Exception as e:
            db.session.rollback()
            flash(f'Kayıt sırasında bir hata oluştu: {str(e)}', 'danger')
            return render_template('add_student.html')
            
    return render_template('add_student.html')

@app.route('/students/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_student(id):
    student = Student.query.get_or_404(id)
    if request.method == 'POST':
        student.name = request.form['name']
        student.surname = request.form['surname']
        student.school_number = request.form['school_number']
        student.class_name = request.form['class_name']
        student.email = request.form.get('email')
        student.phone = request.form.get('phone')
        student.address = request.form.get('address')
        
        db.session.commit()
        flash('Öğrenci bilgileri güncellendi.', 'success')
        return redirect(url_for('students'))
    return render_template('edit_student.html', student=student)

@app.route('/students/delete/<int:id>', methods=['POST'])
@login_required
def delete_student(id):
    student = Student.query.get_or_404(id)
    db.session.delete(student)
    db.session.commit()
    flash('Öğrenci başarıyla silindi.', 'success')
    return redirect(url_for('students'))

@app.route('/books')
@login_required
def books():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    search_query = request.args.get('search', '')
    
    query = Book.query
    
    if search_query:
        query = query.filter(
            or_(
                Book.title.contains(search_query),
                Book.author.contains(search_query),
                Book.isbn.contains(search_query)
            )
        )
    
    # Pagination
    books_pagination = query.order_by(Book.title).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('books.html', books=books_pagination, search_query=search_query)

@app.route('/book/<int:id>')
@login_required
def book_detail(id):
    book = Book.query.get_or_404(id)
    history = Transaction.query.options(joinedload(Transaction.student)).filter_by(book_id=id).order_by(Transaction.issue_date.desc()).all()
    return render_template('book_detail.html', book=book, history=history)

@app.route('/books/add', methods=['GET', 'POST'])
@login_required
def add_book():
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        isbn = request.form['isbn']
        publication_year = request.form.get('publication_year')
        publisher = request.form.get('publisher')
        page_count = request.form.get('page_count')
        category = request.form.get('category')
        description = request.form.get('description')
        
        # Check if book already exists
        existing_book = Book.query.filter_by(isbn=isbn).first()
        if existing_book:
            flash(f'Hata: {isbn} ISBN numaralı kitap ({existing_book.title}) zaten kayıtlı!', 'danger')
            return render_template('add_book.html', 
                                   title=title, author=author, isbn=isbn, 
                                   publication_year=publication_year, publisher=publisher, 
                                   page_count=page_count, category=category, description=description)

        new_book = Book(title=title, author=author, isbn=isbn, publication_year=publication_year, 
                        publisher=publisher, page_count=page_count, category=category, description=description)
        try:
            db.session.add(new_book)
            db.session.commit()
            flash('Kitap başarıyla eklendi!', 'success')
            
            next_page = request.args.get('next')
            if next_page == 'index':
                return redirect(url_for('index'))
            return redirect(url_for('books'))
        except Exception as e:
            db.session.rollback()
            flash(f'Kayıt sırasında bir hata oluştu: {str(e)}', 'danger')
            return render_template('add_book.html')
            
    return render_template('add_book.html')

@app.route('/books/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_book(id):
    book = Book.query.get_or_404(id)
    if request.method == 'POST':
        book.title = request.form['title']
        book.author = request.form['author']
        book.isbn = request.form['isbn']
        book.publication_year = request.form.get('publication_year')
        book.publisher = request.form.get('publisher')
        book.category = request.form.get('category')
        book.description = request.form.get('description')
        
        db.session.commit()
        flash('Kitap bilgileri güncellendi.', 'success')
        return redirect(url_for('books'))
    return render_template('edit_book.html', book=book)

@app.route('/books/delete/<int:id>', methods=['POST'])
@login_required
def delete_book(id):
    book = Book.query.get_or_404(id)
    db.session.delete(book)
    db.session.commit()
    flash('Kitap başarıyla silindi.', 'success')
    return redirect(url_for('books'))

@app.route('/loans', methods=['GET', 'POST'])
@login_required
def loans():
    if request.method == 'POST':
        student_id = request.form['student_id']
        book_id = request.form['book_id']
        
        book = Book.query.get(book_id)
        
        # WATCHER RESTRICTION CHECK
        if getattr(current_user, 'role', 'admin') == 'watcher':
            restricted_number = session.get('watcher_restricted_student')
            if restricted_number:
                student = Student.query.get(student_id)
                if student and str(student.school_number).strip() == restricted_number:
                     flash('Erişim Engellendi! Kendi numaranıza işlem yapamazsınız.', 'danger')
                     return redirect(url_for('loans'))

        if book and book.is_available:
            settings = Settings.query.first()
            loan_period = settings.loan_period if settings else 15
            due_date = datetime.utcnow() + timedelta(days=loan_period)
            
            new_loan = Transaction(student_id=student_id, book_id=book_id, due_date=due_date)
            book.is_available = False
            db.session.add(new_loan)
            db.session.commit()
            flash('Kitap emanet verildi!', 'success')
            
            next_page = request.args.get('next')
            if next_page == 'index':
                return redirect(url_for('index'))
        else:
            flash('Kitap şu anda müsait değil!', 'danger')
        return redirect(url_for('loans'))
        
    active_loans = Transaction.query.options(
        joinedload(Transaction.student), 
        joinedload(Transaction.book)
    ).filter_by(status='active').all()
    students = Student.query.all()
    books = Book.query.filter_by(is_available=True).all()
    return render_template('loans.html', loans=active_loans, students=students, books=books)

@app.route('/return/<int:transaction_id>', methods=['POST'])
@login_required
def return_book(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    
    # WATCHER RESTRICTION CHECK
    if getattr(current_user, 'role', 'admin') == 'watcher':
        restricted_number = session.get('watcher_restricted_student')
        if restricted_number:
            student = transaction.student
            if student and str(student.school_number).strip() == restricted_number: # Changed student_number to school_number
                 flash('Erişim Engellendi! Kendi numaranıza işlem yapamazsınız.', 'danger')
                 return redirect(url_for('loans'))
                 
    book = transaction.book
    book.is_available = True
    transaction.return_date = datetime.utcnow()
    transaction.status = 'returned'
    
    db.session.commit()
    flash('Kitap iade alındı!', 'success')
    return redirect(url_for('loans'))

@app.route('/istatistikler')
@login_required
def statistics():
    # ACCESS CONTROL: WATCHER CANNOT ACCESS
    if getattr(current_user, 'role', 'admin') == 'watcher':
        flash('Nöbetçi hesaplarının bu sayfaya erişim yetkisi yoktur.', 'danger')
        return redirect(url_for('index'))
    return render_template('statistics.html')

@app.route('/api/stats/students/top')
@login_required
def get_top_students():
    # En çok kitap okuyan öğrenciler (Count based)
    # Tüm öğrencileri çekip Python'da sıralayarak Classes mantığıyla birebir uyumlu hale getirelim
    
    students = db.session.query(
        Student.name, 
        Student.surname, 
        Student.class_name, 
        func.count(Transaction.id).label('total')
    ).outerjoin(Transaction, (Student.id == Transaction.student_id) & (Transaction.status == 'returned'))\
     .group_by(Student.id)\
     .order_by(desc('total'))\
     .limit(10).all()
    
    return jsonify([{
        'name': f"{s.name} {s.surname}",
        'class_name': s.class_name,
        'total': s.total
    } for s in students])

@app.route('/api/stats/students/bottom')
@login_required
def get_bottom_students():
    # En az kitap okuyan öğrenciler
    students = db.session.query(
        Student.name, 
        Student.surname, 
        Student.class_name, 
        func.count(Transaction.id).label('total')
    ).outerjoin(Transaction, (Student.id == Transaction.student_id) & (Transaction.status == 'returned'))\
     .group_by(Student.id)\
     .order_by('total')\
     .limit(10).all()
     
    return jsonify([{
        'name': f"{s.name} {s.surname}",
        'class_name': s.class_name,
        'total': s.total
    } for s in students])

@app.route('/api/stats/classes/top')
@login_required
def get_top_classes():
    # En çok okuyan sınıflar (KİTAP SAYISINA GÖRE)
    classes = db.session.query(
        Student.class_name, 
        func.count(Transaction.id).label('total_books')
    ).join(Transaction, Student.id == Transaction.student_id)\
     .filter(Transaction.status == 'returned')\
     .group_by(Student.class_name)\
     .order_by(desc('total_books'))\
     .limit(20).all()
    
    return jsonify([{
        'class_name': c.class_name,
        'total': c.total_books
    } for c in classes])

@app.route('/api/stats/classes/bottom')
@login_required
def get_bottom_classes():
    # En az okuyan sınıflar (KİTAP SAYISINA GÖRE)
    classes = db.session.query(
        Student.class_name, 
        func.count(Transaction.id).label('total_books')
    ).join(Transaction, Student.id == Transaction.student_id)\
     .filter(Transaction.status == 'returned')\
     .group_by(Student.class_name)\
     .order_by('total_books')\
     .limit(20).all()
        
    return jsonify([{
        'class_name': c.class_name,
        'total': c.total_books
    } for c in classes])

@app.route('/api/stats/classes/<path:class_name>')
@login_required
def get_class_details(class_name):
    # Sınıf detayları - O sınıftaki öğrencilerin kitap okuma sayıları
    students = db.session.query(
        Student.name, 
        Student.surname,
        Student.class_name,
        func.count(Transaction.id).label('total')
    ).outerjoin(Transaction, (Student.id == Transaction.student_id) & (Transaction.status == 'returned'))\
     .filter(Student.class_name == class_name)\
     .group_by(Student.id)\
     .order_by(desc('total')).all()
     
    return jsonify([{
        'name': f"{s.name} {s.surname}",
        'class_name': s.class_name,
        'total': s.total
    } for s in students])

@app.route('/api/stats/popular')
@login_required
def get_popular_books():
    books = db.session.query(
        Book.title, 
        Book.author,
        func.count(Transaction.id).label('total')
    ).join(Transaction).filter(Transaction.status == 'returned').group_by(Book.id).order_by(desc('total')).limit(20).all()
    
    return jsonify([{
        'title': b.title,
        'author': b.author,
        'total': b.total
    } for b in books])

@app.route('/api/get-book-details')
@login_required
def api_get_book_details():
    isbn = request.args.get('isbn')
    if not isbn:
        return jsonify({'error': 'ISBN required'}), 400
    
    # Use the helper function
    book_info = get_book_details(isbn)
    
    if book_info:
        return jsonify(book_info)
    else:
        return jsonify({'error': 'Book not found'}), 404

@app.route('/ayarlar', methods=['GET', 'POST'])
@login_required
def settings():
    # ALLOW ALL USERS (Admin + Watcher)
    settings = Settings.query.first()
    if not settings:
        settings = Settings(loan_period=15, school_name='Kütüphane Otomasyonu')
        db.session.add(settings)
        db.session.commit()
        
    if request.method == 'POST':
        # SECURITY CHECK: WATCHERS CANNOT CHANGE SETTINGS
        if getattr(current_user, 'role', 'admin') == 'watcher':
             flash('Yetkisiz işlem! Nöbetçi hesapları ayarları değiştiremez.', 'danger')
             return redirect(url_for('settings'))

        # --- PASSWORD CHANGE LOGIC ---
        if 'change_password_submit' in request.form:
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not current_user.check_password(current_password):
                flash('Mevcut şifre hatalı!', 'danger')
            elif new_password != confirm_password:
                flash('Yeni şifreler uyuşmuyor!', 'danger')
            else:
                current_user.set_password(new_password)
                db.session.commit()
                flash('Şifreniz başarıyla güncellendi.', 'success')
            return redirect(url_for('settings'))

        # --- BOOK IMPORT LOGIC ---
        elif 'import_books_file' in request.files:
            file = request.files['import_books_file']
            if file and file.filename.endswith(('.xlsx', '.xls')):
                try:
                    import pandas as pd
                    df = pd.read_excel(file)
                    
                    # Expected columns: KitapAdı, Yazar, ISBN, Yayınevi, Kategori, BasımYılı, Sayfa
                    
                    added_count = 0
                    skipped_count = 0
                    
                    for index, row in df.iterrows():
                        try:
                            # Basic validation
                            if pd.isna(row.get('KitapAdı')) or pd.isna(row.get('Yazar')) or pd.isna(row.get('ISBN')):
                                skipped_count += 1
                                continue
                                
                            isbn = str(row.get('ISBN')).strip()
                            if isinstance(row.get('ISBN'), float): # Handle excel float logic for numeric-like ISBNs
                                isbn = str(int(row.get('ISBN')))
                            
                            # Check existence
                            existing = Book.query.filter_by(isbn=isbn).first()
                            if existing:
                                skipped_count += 1
                                continue
                                
                            title = str(row.get('KitapAdı')).strip().upper()
                            author = str(row.get('Yazar')).strip().title()
                            publisher = str(row.get('Yayınevi')).strip() if not pd.isna(row.get('Yayınevi')) else None
                            category = str(row.get('Kategori')).strip() if not pd.isna(row.get('Kategori')) else None
                            
                            pub_year = None
                            if not pd.isna(row.get('BasımYılı')):
                                try:
                                    pub_year = int(row.get('BasımYılı'))
                                except: pass
                                
                            page_count = None
                            if not pd.isna(row.get('Sayfa')):
                                try:
                                    page_count = int(row.get('Sayfa'))
                                except: pass
                            
                            new_book = Book(
                                title=title,
                                author=author,
                                isbn=isbn,
                                publisher=publisher,
                                category=category,
                                publication_year=pub_year,
                                page_count=page_count
                            )
                            db.session.add(new_book)
                            added_count += 1
                            
                        except Exception as e:
                            print(f"Error processing book row {index}: {e}")
                            skipped_count += 1
                            
                    db.session.commit()
                    flash(f'Kitap aktarımı tamamlandı: {added_count} kitap eklendi, {skipped_count} kayıt atlandı.', 'success')
                    
                except Exception as e:
                    flash(f'Kitap dosyası işlenirken hata oluştu: {str(e)}', 'danger')
            else:
                 flash('Lütfen geçerli bir Excel dosyası (.xlsx) yükleyin.', 'warning')
            return redirect(url_for('settings'))

        # --- STUDENT IMPORT LOGIC (Existing) ---
        elif 'import_file' in request.files:
            file = request.files['import_file']
            if file and file.filename.endswith(('.xlsx', '.xls')):
                try:
                    import pandas as pd
                    df = pd.read_excel(file)
                    
                    # Expected columns: No, Ad, Soyad, Sınıf
                    # Optional: Email, Telefon, Adres
                    
                    added_count = 0
                    skipped_count = 0
                    
                    for index, row in df.iterrows():
                        try:
                            # Basic validation
                            if pd.isna(row['No']) or pd.isna(row['Ad']) or pd.isna(row['Soyad']):
                                skipped_count += 1
                                continue
                                
                            school_number = str(int(row['No'])) if isinstance(row['No'], (int, float)) else str(row['No']).strip()
                            
                            # Check existence
                            existing = Student.query.filter_by(school_number=school_number).first()
                            if existing:
                                skipped_count += 1
                                continue
                                
                            name = str(row['Ad']).strip().upper()
                            surname = str(row['Soyad']).strip().upper()
                            class_name = str(row['Sınıf']).strip().upper() if not pd.isna(row['Sınıf']) else 'GENEL'
                            email = str(row['Email']).strip() if 'Email' in df.columns and not pd.isna(row['Email']) else None
                            phone = str(row['Telefon']).strip() if 'Telefon' in df.columns and not pd.isna(row['Telefon']) else None
                            address = str(row['Adres']).strip() if 'Adres' in df.columns and not pd.isna(row['Adres']) else None
                            
                            new_student = Student(
                                name=name,
                                surname=surname,
                                school_number=school_number,
                                class_name=class_name,
                                email=email,
                                phone=phone,
                                address=address
                            )
                            db.session.add(new_student)
                            added_count += 1
                            
                        except Exception as e:
                            print(f"Error processing row {index}: {e}")
                            skipped_count += 1
                            
                    db.session.commit()
                    flash(f'Toplu aktarım tamamlandı: {added_count} öğrenci eklendi, {skipped_count} kayıt atlandı (zaten var veya hatalı).', 'success')
                    
                except Exception as e:
                    flash(f'Dosya işlenirken hata oluştu: {str(e)}', 'danger')
            else:
                 flash('Lütfen geçerli bir Excel dosyası (.xlsx) yükleyin.', 'warning')
                 
        # --- SETTINGS UPDATE LOGIC ---
        elif 'school_name' in request.form:
            settings.school_name = request.form['school_name']
            settings.loan_period = int(request.form['loan_period'])
            if 'theme' in request.form:
                settings.theme = request.form['theme']
            
            # Device Verification Toggle
            if 'device_verification_toggle' in request.form:
                 current_user.device_verification_enabled = True
            else:
                 # Checkbox not sent implies False
                 # Only if this form submission is about main settings (check for school_name existence)
                 if 'school_name' in request.form:
                     current_user.device_verification_enabled = False

            db.session.commit()
            flash('Ayarlar güncellendi!', 'success')
            
        return redirect(url_for('settings'))
        
    # Get Banned IPs for display
    banned_ips = list(guardian.banned_ips)
    return render_template('settings.html', settings=settings, banned_ips=banned_ips)

@app.route('/reports')
@login_required
def reports():
    # Öğrencileri okudukları kitap sayısına göre sırala
    students = db.session.query(Student, func.count(Transaction.id).label('read_count'))\
        .outerjoin(Transaction, (Student.id == Transaction.student_id) & (Transaction.status == 'returned'))\
        .group_by(Student.id)\
        .order_by(desc('read_count'))\
        .all()
        
    transactions = Transaction.query.order_by(Transaction.issue_date.desc()).all()
    books = Book.query.order_by(Book.title).all()
    return render_template('reports.html', students=students, books=books, transactions=transactions)

@app.route('/api/calendar/events')
@login_required
def calendar_events():
    # Active loans only
    loans = Transaction.query.options(
        joinedload(Transaction.student),
        joinedload(Transaction.book)
    ).filter_by(status='active').all()
    events = []
    
    for loan in loans:
        student_name = f"{loan.student.name} {loan.student.surname}"
        book_title = loan.book.title
        due_date = loan.due_date.strftime('%Y-%m-%d')
        
        # Color coding: Red if overdue, Orange if nearing due date (within 3 days), Blue otherwise
        color = '#3788d8' # default blue
        if loan.due_date < datetime.utcnow():
            color = '#e74c3c' # red
        elif loan.due_date < datetime.utcnow() + timedelta(days=3):
            color = '#f39c12' # warning orange
            
        events.append({
            'title': f"{student_name} - {book_title}",
            'start': due_date,
            'color': color,
            'url': url_for('student_detail', id=loan.student_id)
        })
        
    return jsonify(events)

@app.route('/guvenlik')
@login_required
def security_dashboard():
    # 1. Read Banned IPs
    banned_data = {}
    try:
        import json, os
        from guvenlik import ShieldConfig
        if os.path.exists(ShieldConfig.BAN_FILE):
            with open(ShieldConfig.BAN_FILE, 'r') as f:
                banned_data = json.load(f)
    except:
        pass

    # 2. Read Logs (Last 100)
    logs = []
    total_threats = 0
    try:
        log_file = 'titanium_defense.log'
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                lines = f.readlines()
                total_threats = len(lines)
                # Parse last 100 lines reverse
                for line in reversed(lines[-100:]):
                    try:
                        logs.append(json.loads(line))
                    except:
                        pass
    except:
        pass
        
    stats = {
        'total_threats': total_threats,
        'banned_count': len(banned_data)
    }
    
    return render_template('security_dashboard.html', logs=logs, banned_ips=banned_data, stats=stats)


@app.route('/api/security/ip-action', methods=['POST'])
@login_required
def security_ip_action():
    # Only Admin (or authorized role) should do this
    if getattr(current_user, 'role', 'admin') == 'watcher':
         return jsonify({'success': False, 'message': 'Yetkisiz işlem.'}), 403

    data = request.get_json()
    ip = data.get('ip')
    action = data.get('action') # 'ban', 'unban', 'reset'
    
    if not ip or not action:
        return jsonify({'success': False, 'message': 'Eksik parametre.'}), 400

    try:
        if action == 'ban':
            guardian.manual_ban_ip(ip, reason="Yönetici Tarafindan Yasaklandi")
            message = f"{ip} adresi yasaklandi."
            
        elif action == 'unban':
            guardian.manual_unban_ip(ip)
            message = f"{ip} adresinin yasağı kaldırıldı."
            
        elif action == 'reset':
            guardian.reset_ip_status(ip)
            message = f"{ip} adresi temize çıkarıldı (Reset)."
        else:
            return jsonify({'success': False, 'message': 'Geçersiz işlem.'}), 400
            
        return jsonify({'success': True, 'message': message})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
def get_weather():
    try:
        # Simple mock or fetch - for now mock to avoid API key issues
        return jsonify({
            'temp': '22',
            'description': 'Güneşli'
        })
    except:
        return jsonify(None)

def link_callback(uri, rel):
    """
    Convert HTML URIs to absolute system paths so xhtml2pdf can access those resources
    """
    # use short variable names
    sUrl = '/static/'
    sRoot = os.path.join(application_path, 'static')

    # convert URIs to absolute system paths
    if uri.startswith(sUrl):
        path = os.path.join(sRoot, uri.replace(sUrl, ""))
    else:
        return uri  # handle absolute uri (ie: http://some.tld/foo.png)

    # make sure that file exists
    if not os.path.isfile(path):
        raise Exception(
                'media URI must start with %s or file not found' % sUrl)
    return path

@app.route('/reports/export/<type>')
@login_required
def export_report_pdf(type):
    settings = Settings.query.first()
    school_name = settings.school_name if settings else "Kütüphane Sistemi"
    
    data = []
    title = ""
    report_category = "" # For template conditional logic if needed
    
    # --- EXISTING REPORTS ---
    if type == 'student-list':
        title = "Öğrenci Okuma Raporu (Genel)"
        data = db.session.query(Student, db.func.count(Transaction.id).label('read_count'))\
            .outerjoin(Transaction, (Student.id == Transaction.student_id) & (Transaction.status == 'returned'))\
            .group_by(Student.id)\
            .order_by(desc('read_count'))\
            .all()
    elif type == 'book-list':
        title = "Kitap Envanter Raporu"
        data = Book.query.order_by(Book.title).all()
    elif type == 'transaction-list':
        title = "Detaylı Hareket Geçmişi"
        data = Transaction.query.order_by(Transaction.issue_date.desc()).all()

    # --- STATISTICS REPORTS (NEW) ---
    elif type.startswith('stats-students'):
        category = request.args.get('category', 'top') # top or bottom
        
        # Base query for all students
        students_all = db.session.query(
            Student, 
            func.count(Transaction.id).label('read_count')
        ).outerjoin(Transaction, (Student.id == Transaction.student_id) & (Transaction.status == 'returned'))\
         .group_by(Student.id).all()
         
        # Sort Descending (Top logic)
        sorted_desc = sorted(students_all, key=lambda x: x.read_count, reverse=True)
        
        if category == 'top':
            title = "En Çok Kitap Okuyan Öğrenciler (Top 10)"
            data = sorted_desc[:10]
        else:
            title = "En Az Kitap Okuyan Öğrenciler (Top 10 Hariç)"
            # Exclude Top 10
            remaining = sorted_desc[10:]
            # Sort Ascending
            sorted_asc = sorted(remaining, key=lambda x: x.read_count)
            data = sorted_asc[:10]
            
        type = 'student-rank-list'

    elif type.startswith('stats-classes'):
        category = request.args.get('category', 'top')
        
        # Base query for all classes (Book Count based)
        all_classes_names = db.session.query(Student.class_name).distinct().all()
        class_stats = []
        
        for cls in all_classes_names:
            class_name = cls[0]
            total_books = db.session.query(func.count(Transaction.id))\
                .join(Student, Transaction.student_id == Student.id)\
                .filter(Student.class_name == class_name, Transaction.status == 'returned')\
                .scalar() or 0
            # For template compatibility, we need a structure. 
            # Student rank list template expects an object with 'name' or 'class_name' and 'read_count'
            # Let's create a dummy object or dict that template handles
            # But the template uses 'row.Student.name' likely if it's a tuple (Student, count)
            # OR creates a simple object
            class_stats.append({'class_name': class_name, 'read_count': total_books})
            
        # Sort Descending
        sorted_desc = sorted(class_stats, key=lambda x: x['read_count'], reverse=True)
        
        if category == 'top':
            title = "En Çok Okuyan Sınıflar (Top 20)"
            data = sorted_desc[:20]
        else:
            title = "En Az Okuyan Sınıflar (Top 20 Hariç)"
            # Exclude Top 20
            remaining = sorted_desc[20:]
            # Sort Ascending
            sorted_asc = sorted(remaining, key=lambda x: x['read_count'])
            data = sorted_asc[:20]
            
    elif type == 'stats-books-popular':
        title = "En Popüler Kitaplar (Top 20)"
        data = db.session.query(Book, func.count(Transaction.id).label('read_count'))\
            .join(Transaction, Book.id == Transaction.book_id)\
            .group_by(Book.id)\
            .order_by(desc('read_count'))\
            .limit(20)\
            .all()

    elif type == 'stats-class-detail':
        class_name = request.args.get('class_name')
        if not class_name:
            flash('Sınıf adı belirtilmedi.', 'danger')
            return redirect(url_for('statistics'))
            
        title = f"{class_name} Sınıfı Okuma Raporu"
        # Re-using the query logic from get_class_details API but for template
        data = db.session.query(
            Student,
            func.count(Transaction.id).label('read_count')
        ).outerjoin(Transaction, (Student.id == Transaction.student_id) & (Transaction.status == 'returned'))\
         .filter(Student.class_name == class_name)\
         .group_by(Student.id)\
         .order_by(desc('read_count')).all()
         
        # We can reuse student-rank-list template since structure is similar (Student obj, count)
        type = 'student-rank-list' 

    else:
        flash('Geçersiz rapor türü.', 'danger')
        return redirect(url_for('reports'))

    return render_template('pdf_report.html', 
                           title=title, 
                           school_name=school_name,
                           date=datetime.now().strftime('%d.%m.%Y'),
                           user=current_user.username,
                           report_type=type,
                           data=data)

@app.route('/student/<int:id>/id-card')
@login_required
def student_id_card(id):
    student = Student.query.get_or_404(id)
    return render_template('id_card.html', student=student)


    

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    

    if not DEBUG_MODE:
        Timer(1.5, open_browser).start()
    


    if DEBUG_MODE:


         pass



    app.run(host='0.0.0.0', debug=DEBUG_MODE)
