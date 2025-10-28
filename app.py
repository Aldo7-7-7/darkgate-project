from flask import Flask, render_template, request, redirect, url_for, flash, make_response, send_file
import os, sqlite3, bcrypt, jwt, requests, hashlib, uuid
from datetime import datetime, timedelta
from models import DB, init_db
from pathlib import Path
from dotenv import load_dotenv
from flask_mail import Mail, Message  # <-- NUEVA IMPORTACIÓN

# Cargar variables de entorno (para desarrollo local)
load_dotenv()

# ===============================================
# CONFIGURACIÓN BÁSICA DE LA APLICACIÓN
# ===============================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change_me_securely')

# ===============================================
# CONFIGURACIÓN DE CORREO (Flask-Mail)
# ===============================================
# **IMPORTANTE:** Necesitas agregar MAIL_PASSWORD a las variables de entorno de Render
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_SENDER') 
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD') # Lee de Render/Env
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_SENDER')

mail = Mail(app)
# ===============================================

DB_PATH = Path('database.db')
if not DB_PATH.exists():
    init_db()

def get_db_conn():
    # Usar DB del archivo models.py
    return sqlite3.connect(DB)

# ===============================================
# JWT y RSA CONFIGURACIÓN
# ===============================================
# Cargar claves JWT (para firmas RSA)
JWT_PRIVATE_KEY_PATH = os.getenv('JWT_PRIVATE_KEY_PATH', 'keys/private.pem')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM','RS256')

PRIVATE_KEY = None
if Path(JWT_PRIVATE_KEY_PATH).exists():
    # Solo en Render/Producción
    PRIVATE_KEY = open(JWT_PRIVATE_KEY_PATH,'rb').read()

# ===============================================
# FUNCIÓN DE SEGURIDAD: VALIDACIÓN DE RECAPTCHA
# ===============================================
def validar_recaptcha(response_token):
    secreto = os.environ.get("RECAPTCHA_SECRET_KEY")
    if not secreto:
        print("ADVERTENCIA: RECAPTCHA_SECRET_KEY no está configurada.")
        return False

    payload = {
        'secret': secreto,
        'response': response_token
    }
    r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    resultado = r.json()
    return resultado.get('success', False)
# ===============================================


@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        # Nota: Idealmente se debe añadir reCAPTCHA también al registro
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].encode('utf-8')
        ph = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
        conn = get_db_conn()
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username,email,password_hash,phone,created_at) VALUES (?,?,?,?,datetime("now"))',
                      (username,email,ph, request.form.get('phone','')))
            conn.commit()
            flash('Registro exitoso. Ya puede iniciar sesión.','success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Error: {}'.format(e),'danger')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        # 1. Validación de reCAPTCHA ANTES DE TODO
        recaptcha_response = request.form.get('g-recaptcha-response')
        
        if not validar_recaptcha(recaptcha_response):
            flash("¡Fallo en la verificación de reCAPTCHA! Inténtalo de nuevo.", "error")
            return redirect(url_for('login'))
        
        # 2. Lógica de Login (si reCAPTCHA es exitoso)
        username = request.form['username'].strip()
        password = request.form['password'].encode('utf-8')

        conn = get_db_conn()
        c = conn.cursor()
        c.execute('SELECT id,password_hash FROM users WHERE username=?',(username,))
        row = c.fetchone()
        conn.close()
        
        if row and bcrypt.checkpw(password, row[1].encode('utf-8')):
            # Generación de JWT (usando RS256 si hay clave, o HS256 si es desarrollo)
            payload = {
                'sub': row[0],
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(hours=1)
            }
            if PRIVATE_KEY:
                token = jwt.encode(payload, PRIVATE_KEY, algorithm=JWT_ALGORITHM)
            else:
                # Usar SECRET_KEY de Flask si no hay clave RSA (MODO DEV)
                token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
            
            resp = make_response(redirect(url_for('dashboard')))
            # secure=True es necesario porque Render ya usa HTTPS
            resp.set_cookie('access_token', token, httponly=True, secure=True, samesite='Lax') 
            return resp
        else:
            flash('Usuario o contraseña incorrecta','danger')
    
    # Pasar la clave pública del sitio para mostrar el widget en el HTML
    return render_template('login.html', recaptcha_site_key=os.getenv('RECAPTCHA_SITE_KEY',''))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# ===============================================
# RUTAS DE RECUPERACIÓN DE CONTRASEÑA (NUEVO)
# ===============================================

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_conn()
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE email=?', (email,))
        user_id = c.fetchone()
        conn.close()

        if user_id:
            user_id = user_id[0]
            # 1. Generar token JWT con tiempo limitado (ej. 30 minutos)
            payload = {
                'user_id': user_id,
                'exp': datetime.utcnow() + timedelta(minutes=30)
            }
            # Usar la clave de la app para firmar el token de recuperación
            reset_token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

            # 2. Enviar email
            reset_url = url_for('reset_password', token=reset_token, _external=True)
            msg = Message('Restablecimiento de Contraseña DarkGate', recipients=[email])
            msg.body = f'Para restablecer tu contraseña, haz clic en el siguiente enlace: {reset_url}'
            
            try:
                mail.send(msg)
                flash('Se ha enviado un correo con instrucciones para restablecer tu contraseña.', 'info')
            except Exception as e:
                # Esto atrapará errores de conexión o autenticación de correo
                flash(f'Error al enviar el correo. Revisa la configuración MAIL_PASSWORD en Render. Error: {e}', 'danger')
        else:
            flash('No existe una cuenta con ese correo electrónico.', 'danger')
        
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Decodificar el token usando la clave de la app
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = data.get('user_id')
    except jwt.ExpiredSignatureError:
        flash('El token de restablecimiento ha expirado. Solicita uno nuevo.', 'danger')
        return redirect(url_for('forgot_password'))
    except (jwt.InvalidTokenError, jwt.DecodeError):
        flash('Token de restablecimiento inválido.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password'].encode('utf-8')
        ph = bcrypt.hashpw(new_password, bcrypt.gensalt()).decode('utf-8')
        
        conn = get_db_conn()
        c = conn.cursor()
        c.execute('UPDATE users SET password_hash=? WHERE id=?', (ph, user_id))
        conn.commit()
        conn.close()
        
        flash('Tu contraseña ha sido restablecida con éxito. Ya puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# ===============================================
# RUTAS DE PDF Y FIRMA
# ===============================================
@app.route('/generate_pdf')
def generate_pdf():
    # Crear un PDF de ejemplo sencillo
    from reportlab.pdfgen import canvas
    pdf_path = 'static/example_document.pdf'
    c = canvas.Canvas(pdf_path)
    c.drawString(100,750,"DarkGate - Documento de Prueba")
    c.drawString(100,730,"Fecha: {}".format(datetime.utcnow().isoformat()))
    c.save()
    return send_file(pdf_path, as_attachment=True)

# Firma del PDF (hash + firma RSA) -> devuelve archivo .sig
@app.route('/sign_pdf')
def sign_pdf_route():
    pdf_path = 'static/example_document.pdf'
    sig_path = 'static/example_document.pdf.sig'
    if not os.path.exists(pdf_path):
        return "Primero generar el PDF en /generate_pdf", 400
    # calcular hash
    with open(pdf_path,'rb') as f:
        pdf_bytes = f.read()
    digest = hashlib.sha256(pdf_bytes).digest()
    # firmar con clave privada si existe
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    if not os.path.exists(JWT_PRIVATE_KEY_PATH):
        return "No existe la clave privada en keys/private.pem. Genere las claves.", 500
    with open(JWT_PRIVATE_KEY_PATH,'rb') as kf:
        private = load_pem_private_key(kf.read(), password=None)
    signature = private.sign(digest, padding.PKCS1v15(), hashes.SHA256())
    with open(sig_path,'wb') as sf:
        sf.write(signature)
    return send_file(sig_path, as_attachment=True)

if __name__ == '__main__':
    # Usar 0.0.0.0 y puerto 5000 para compatibilidad con Render y entornos de producción
    app.run(host='0.0.0.0', port=5000, debug=True)
