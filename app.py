from flask import Flask, render_template, request, redirect, url_for, flash, make_response, send_file
import os, sqlite3, bcrypt, jwt, requests, hashlib, uuid, io # 'io' es necesario para generar PDF en memoria
from datetime import datetime, timedelta
from models import DB, init_db
from pathlib import Path
from dotenv import load_dotenv
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename 

# Cargar variables de entorno (para desarrollo local)
load_dotenv()

# ===============================================
# CONFIGURACIÓN BÁSICA DE LA APLICACIÓN
# ===============================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change_me_securely')
app.config['UPLOAD_FOLDER'] = 'temp_uploads' # Carpeta temporal para verificación de archivos

# Asegúrate de que la carpeta de subida exista
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# ===============================================
# CONFIGURACIÓN DE CORREO (Flask-Mail)
# ===============================================
# **IMPORTANTE:** MAIL_PASSWORD se lee desde Render Environment Variables
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_SENDER') 
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_SENDER')

mail = Mail(app)
# ===============================================

DB_PATH = Path('database.db')
if not DB_PATH.exists():
    init_db()

def get_db_conn():
    return sqlite3.connect(DB)

# ===============================================
# JWT y RSA CONFIGURACIÓN
# ===============================================
# Rutas a las claves para firmar (private) y verificar (public)
JWT_PRIVATE_KEY_PATH = os.getenv('JWT_PRIVATE_KEY_PATH', 'keys/private.pem')
JWT_PUBLIC_KEY_PATH = os.getenv('JWT_PUBLIC_KEY_PATH', 'keys/public.pem') 
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM','RS256')

PRIVATE_KEY = None
if Path(JWT_PRIVATE_KEY_PATH).exists():
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
                # Usa la SECRET_KEY de Flask si no se encontró la clave RSA (Modo DEV)
                token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
            
            resp = make_response(redirect(url_for('dashboard')))
            # secure=True es crucial para HTTPS en Render
            resp.set_cookie('access_token', token, httponly=True, secure=True, samesite='Lax') 
            return resp
        else:
            flash('Usuario o contraseña incorrecta','danger')
    
    return render_template('login.html', recaptcha_site_key=os.getenv('RECAPTCHA_SITE_KEY',''))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# ===============================================
# RUTAS DE RECUPERACIÓN DE CONTRASEÑA
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
            payload = {
                'user_id': user_id,
                'exp': datetime.utcnow() + timedelta(minutes=30)
            }
            reset_token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

            reset_url = url_for('reset_password', token=reset_token, _external=True)
            msg = Message('Restablecimiento de Contraseña DarkGate', recipients=[email])
            msg.body = f'Para restablecer tu contraseña, haz clic en el siguiente enlace: {reset_url}'
            
            try:
                mail.send(msg)
                flash('Se ha enviado un correo con instrucciones para restablecer tu contraseña.', 'info')
            except Exception as e:
                flash(f'Error al enviar el correo. Revisa la configuración MAIL_PASSWORD en Render. Error: {e}', 'danger')
        else:
            flash('No existe una cuenta con ese correo electrónico.', 'danger')
        
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
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
# RUTAS DE PDF Y FIRMA DIGITAL
# ===============================================
@app.route('/generate_pdf')
def generate_pdf():
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter # Importación necesaria para el tamaño de página
    
    # Usar un buffer de memoria (io.BytesIO) para evitar problemas de permisos de escritura en Render
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    
    c.drawString(100,750,"DarkGate - Documento de Prueba Final")
    c.drawString(100,730,"Proyecto de Seguridad (JWT, reCAPTCHA)")
    c.drawString(100,710,"Fecha: {}".format(datetime.utcnow().isoformat()))
    
    c.showPage()
    c.save()
    
    # Mueve el cursor al inicio del buffer antes de enviarlo
    buffer.seek(0) 
    
    # Envía el archivo generado en memoria
    return send_file(
        buffer,
        as_attachment=True,
        download_name='example_document.pdf', 
        mimetype='application/pdf'
    )

# Firma del PDF (hash + firma RSA) -> devuelve archivo .sig
@app.route('/sign_pdf')
def sign_pdf_route():
    # Esta ruta requiere que el PDF esté en disco para ser leído, lo cual puede fallar en Render.
    # El usuario debe usar la función /generate_pdf para obtener el PDF primero.
    pdf_path = 'static/example_document.pdf'
    sig_path = 'static/example_document.pdf.sig'
    
    # Nota: Si se usara la generación en memoria, este archivo no existiría en disco.
    # Por simplicidad, asumimos que el PDF está disponible o el usuario lo ha guardado.
    # En un sistema real, el usuario subiría el archivo a firmar.
    if not os.path.exists(pdf_path):
        return "Primero genere el PDF y asegúrese de que esté disponible para la firma. En un sistema real, el usuario subiría el PDF a firmar.", 400
    
    # calcular hash
    with open(pdf_path,'rb') as f:
        pdf_bytes = f.read()
    digest = hashlib.sha256(pdf_bytes).digest()
    
    # firmar con clave privada si existe
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    
    if not os.path.exists(JWT_PRIVATE_KEY_PATH):
        return "No existe la clave privada en keys/private.pem. Genere las claves (openssl).", 500
    
    with open(JWT_PRIVATE_KEY_PATH,'rb') as kf:
        private = load_pem_private_key(kf.read(), password=None)
        
    signature = private.sign(digest, padding.PKCS1v15(), hashes.SHA256())
    
    # Guarda la firma en disco para enviarla al usuario
    with open(sig_path,'wb') as sf:
        sf.write(signature)
        
    return send_file(sig_path, as_attachment=True)


@app.route('/verify_signature', methods=['GET', 'POST'])
def verify_signature():
    if request.method == 'POST':
        # 1. Verificar si se subieron ambos archivos
        if 'pdf_file' not in request.files or 'sig_file' not in request.files:
            flash('Debes subir el archivo PDF y su firma (.sig).', 'danger')
            return redirect(url_for('verify_signature'))

        pdf_file = request.files['pdf_file']
        sig_file = request.files['sig_file']

        if pdf_file.filename == '' or sig_file.filename == '':
            flash('Debes seleccionar archivos válidos.', 'danger')
            return redirect(url_for('verify_signature'))
        
        # 2. Leer archivos y calcular hash del PDF
        pdf_bytes = pdf_file.read()
        sig_bytes = sig_file.read()
        digest = hashlib.sha256(pdf_bytes).digest()

        # 3. Cargar clave pública
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        
        if not os.path.exists(JWT_PUBLIC_KEY_PATH):
            flash("Error: No se encontró la clave pública (keys/public.pem) en el servidor.", 'danger')
            return redirect(url_for('verify_signature'))

        with open(JWT_PUBLIC_KEY_PATH, 'rb') as kf:
            public_key = load_pem_public_key(kf.read())

        # 4. Verificar la firma
        try:
            public_key.verify(
                sig_bytes,
                digest,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            flash(' ¡Firma digital VERIFICADA! El documento es auténtico y no ha sido alterado.', 'success')
        except Exception as e:
            flash(f' ¡Firma INVÁLIDA! El documento fue alterado o no fue firmado con nuestra clave. Error: {e}', 'danger')
        
        return redirect(url_for('verify_signature'))

    return render_template('verify_signature.html')

if __name__ == '__main__':
    # Usar 0.0.0.0 y puerto 5000 para compatibilidad con Render y entornos de producción
    app.run(host='0.0.0.0', port=5000, debug=True)
