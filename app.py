from flask import Flask, render_template, request, redirect, url_for, flash, make_response, send_file
import os, sqlite3, bcrypt, jwt, requests, hashlib, uuid, io # 'io' es para generación de PDF en memoria
from datetime import datetime, timedelta
from models import DB, init_db
from pathlib import Path
from dotenv import load_dotenv
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename 
from fpdf import FPDF # <-- FIX para generación de PDF sin dependencias de sistema
from functools import wraps # Para el decorador de autenticación

# Cargar variables de entorno (para desarrollo local)
load_dotenv()

# ===============================================
# CONFIGURACIÓN BÁSICA DE LA APLICACIÓN
# ===============================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change_me_securely')
app.config['UPLOAD_FOLDER'] = 'temp_uploads' 

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# ===============================================
# CONFIGURACIÓN DE CORREO (Flask-Mail)
# ===============================================
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

# ===============================================
# DECORADOR DE AUTENTICACIÓN JWT (RSA/HS256)
# ===============================================
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('access_token')

        if not token:
            flash('Acceso denegado. Por favor, inicia sesión.', 'danger')
            return redirect(url_for('login'))
        
        try:
            # Intentar decodificar el token con la clave pública (RSA)
            if JWT_PUBLIC_KEY_PATH and os.path.exists(JWT_PUBLIC_KEY_PATH):
                from cryptography.hazmat.primitives.serialization import load_pem_public_key
                with open(JWT_PUBLIC_KEY_PATH, 'rb') as kf:
                    public_key = load_pem_public_key(kf.read())
                data = jwt.decode(token, public_key, algorithms=[JWT_ALGORITHM])
            else:
                # Decodificar con SECRET_KEY si no hay clave pública (Modo DEV/HS256)
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            
            # Pasar los datos del token a la función decorada
            return f(data, *args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            flash('Tu sesión ha expirado. Por favor, vuelve a iniciar sesión.', 'danger')
            resp = make_response(redirect(url_for('login')))
            resp.set_cookie('access_token', '', expires=0) # Borra la cookie
            return resp
        except jwt.InvalidTokenError:
            flash('Token inválido. Acceso denegado.', 'danger')
            resp = make_response(redirect(url_for('login')))
            resp.set_cookie('access_token', '', expires=0) 
            return resp

    return decorated
# ===============================================


@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
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
            payload = {
                'sub': row[0],
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(hours=1)
            }
            if PRIVATE_KEY:
                token = jwt.encode(payload, PRIVATE_KEY, algorithm=JWT_ALGORITHM)
            else:
                token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
            
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('access_token', token, httponly=True, secure=True, samesite='Lax') 
            return resp
        else:
            flash('Usuario o contraseña incorrecta','danger')
    
    return render_template('login.html', recaptcha_site_key=os.getenv('RECAPTCHA_SITE_KEY',''))

@app.route('/dashboard')
@token_required # <-- RUTA PROTEGIDA
def dashboard(current_user):
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
@token_required # <-- RUTA PROTEGIDA
def generate_pdf(current_user):
    
    # Usamos fpdf2 (alternativa que no usa librerías de sistema operativo)
    from fpdf import FPDF
    
    # Crea la instancia FPDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    # Contenido del PDF
    pdf.cell(200, 10, txt="DarkGate - Documento de Prueba Final", ln=1, align="C")
    pdf.ln(5)
    pdf.cell(200, 10, txt=f"Generado por: Usuario ID {current_user.get('sub')}", ln=1)
    pdf.cell(200, 10, txt="Proyecto de Seguridad (JWT, reCAPTCHA)", ln=1)
    pdf.cell(200, 10, txt=f"Fecha de Creación: {datetime.utcnow().isoformat()}", ln=1)

    # Guarda el PDF en un buffer de memoria
    buffer = io.BytesIO(pdf.output())
    buffer.seek(0)
    
    # Envía el archivo generado en memoria
    return send_file(
        buffer,
        as_attachment=True,
        download_name='document_to_sign.pdf',
        mimetype='application/pdf'
    )

# Firma del PDF (hash + firma RSA) -> devuelve archivo .sig
@app.route('/sign_pdf', methods=['GET', 'POST']) # <-- AHORA ACEPTA POST
@token_required 
def sign_pdf_route(current_user):
    # Si es GET, muestra el formulario
    if request.method == 'GET':
        return render_template('sign_pdf.html')

    # Si es POST, realiza la firma
    if 'pdf_file' not in request.files:
        flash('Debes subir el archivo PDF a firmar.', 'danger')
        return redirect(url_for('sign_pdf_route'))

    pdf_file = request.files['pdf_file']
    if pdf_file.filename == '':
        flash('Debes seleccionar un archivo PDF válido.', 'danger')
        return redirect(url_for('sign_pdf_route'))
    
    # Leer archivo subido y calcular hash
    pdf_bytes = pdf_file.read()
    digest = hashlib.sha256(pdf_bytes).digest()
    
    # firmar con clave privada (RSA)
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    
    if not os.path.exists(JWT_PRIVATE_KEY_PATH):
        return "No existe la clave privada en keys/private.pem. Asegúrese de haber generado las claves (openssl).", 500
    
    with open(JWT_PRIVATE_KEY_PATH,'rb') as kf:
        private = load_pem_private_key(kf.read(), password=None)
        
    signature = private.sign(digest, padding.PKCS1v15(), hashes.SHA256())
    
    # Envía la firma generada en memoria al usuario
    sig_buffer = io.BytesIO(signature)
    sig_buffer.seek(0)
    
    flash('¡Documento firmado exitosamente! Descarga la firma y verifica su autenticidad.', 'success')
    return send_file(
        sig_buffer,
        as_attachment=True,
        download_name='signature_for_' + pdf_file.filename + '.sig',
        mimetype='application/octet-stream'
    )


@app.route('/verify_signature', methods=['GET', 'POST'])
@token_required # <-- RUTA PROTEGIDA
def verify_signature(current_user): # <-- RECIBE DATOS DE SESIÓN
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

