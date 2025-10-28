from flask import Flask, render_template, request, redirect, url_for, flash, make_response, send_file
import os, sqlite3, bcrypt, jwt, requests, hashlib, uuid, io
from datetime import datetime, timedelta
# Importamos get_db_connection para usar la configuración de row_factory de model.py
from models import DB, init_db, get_db_connection
from pathlib import Path
from dotenv import load_dotenv
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename 
from fpdf import FPDF 
from functools import wraps # Para el decorador de autenticación
# Importar módulos necesarios para la firma RSA
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

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
# Inicializa la DB si no existe. Esto también crea el usuario de fábrica.
if not DB_PATH.exists():
    init_db()

def get_db_conn():
    return sqlite3.connect(DB)

# ===============================================
# JWT y RSA CONFIGURACIÓN (para Render)
# ===============================================
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'RS256')

# Cargar claves directamente desde variables de entorno
PRIVATE_KEY = os.environ.get('JWT_PRIVATE_KEY')
PUBLIC_KEY  = os.environ.get('JWT_PUBLIC_KEY')

if PRIVATE_KEY:
    PRIVATE_KEY = PRIVATE_KEY.encode()  # Convertir a bytes
if PUBLIC_KEY:
    PUBLIC_KEY = PUBLIC_KEY.encode()    # Convertir a bytes


# ===============================================
# FUNCIÓN DE SEGURIDAD: VALIDACIÓN DE RECAPTCHA
# ===============================================
def validar_recaptcha(response_token):
    """Verifica el token de respuesta de Google reCAPTCHA."""
    secreto = os.environ.get("RECAPTCHA_SECRET_KEY")
    if not secreto:
        print("ADVERTENCIA: RECAPTCHA_SECRET_KEY no está configurada.")
        # En un entorno de desarrollo sin clave, podrías querer retornar True.
        # En producción, esto DEBERÍA fallar.
        return False

    payload = {
        'secret': secreto,
        'response': response_token
    }
    try:
        r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload, timeout=5)
        resultado = r.json()
        return resultado.get('success', False)
    except requests.RequestException as e:
        print(f"Error al conectar con el servicio reCAPTCHA: {e}")
        return False
# ===============================================

# ===============================================
# DECORADOR DE AUTENTICACIÓN JWT (RSA/HS256)
# ===============================================
def token_required(f):
    """Verifica el token de sesión almacenado en la cookie 'access_token'."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('access_token')

        if not token:
            flash('Acceso denegado. Por favor, inicia sesión.', 'danger')
            return redirect(url_for('login'))
        
        try:
            if PUBLIC_KEY:
                public_key = load_pem_public_key(PUBLIC_KEY)
                data = jwt.decode(token, public_key, algorithms=[JWT_ALGORITHM])
            else:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            
            return f(data, *args, **kwargs)
            
        except jwt.ExpiredSignatureError:
            flash('Tu sesión ha expirado. Por favor, vuelve a iniciar sesión.', 'danger')
            resp = make_response(redirect(url_for('login')))
            resp.set_cookie('access_token', '', expires=0)
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

        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute(
                'INSERT INTO users (username, email, password_hash, phone, created_at) VALUES (?,?,?,?,datetime("now"))',
                (username, email, ph, request.form.get('phone',''))
            )
            conn.commit()

            # Recuperar el ID del usuario recién creado
            user_id = c.lastrowid

            # Generación del JWT inmediatamente
            payload = {
                'sub': user_id,
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(hours=1)
            }

            if PRIVATE_KEY:
                private_key = load_pem_private_key(PRIVATE_KEY, password=None)
                token = jwt.encode(payload, private_key, algorithm=JWT_ALGORITHM)
            else:
                token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

            # Redirigir al dashboard directamente y crear cookie
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('access_token', token, httponly=True, secure=True, samesite='Lax')
            flash('Registro exitoso. Bienvenido.', 'success')
            return resp

        except sqlite3.IntegrityError:
            flash('Error: El nombre de usuario o correo electrónico ya está registrado.', 'danger')
        except Exception as e:
            flash(f'Error al registrar usuario: {e}', 'danger')
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        # 1. Validación de reCAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response', '')
        if not validar_recaptcha(recaptcha_response):
            flash('reCAPTCHA no válido. Intenta de nuevo.', 'danger')
            return render_template('login.html', recaptcha_site_key=os.getenv('RECAPTCHA_SITE_KEY',''))

        # 2. Lógica de Login
        username = request.form['username'].strip()
        password = request.form['password'].encode('utf-8') 

        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT id,password_hash FROM users WHERE username=?', (username,))
        row = c.fetchone()
        conn.close()
        
        if row:
            db_hash_bytes = row['password_hash'].encode('utf-8')

            if bcrypt.checkpw(password, db_hash_bytes):
                # Generación del JWT seguro
                payload = {
                    'sub': row['id'],
                    'iat': datetime.utcnow(),
                    'exp': datetime.utcnow() + timedelta(hours=1)
                }

                try:
                    if PRIVATE_KEY:
                        private_key = load_pem_private_key(PRIVATE_KEY, password=None)
                        token = jwt.encode(payload, private_key, algorithm=JWT_ALGORITHM)
                    else:
                        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
                except Exception as e:
                    flash(f'Error al generar token de sesión: {e}', 'danger')
                    return render_template('login.html', recaptcha_site_key=os.getenv('RECAPTCHA_SITE_KEY',''))

                # Configuración de la cookie segura
                resp = make_response(redirect(url_for('dashboard')))
                resp.set_cookie('access_token', token, httponly=True, secure=True, samesite='Lax')
                flash('Inicio de sesión exitoso.', 'success')
                return resp

        # Si no hay usuario o contraseña incorrecta
        flash('Usuario o contraseña incorrecta', 'danger')

    return render_template('login.html', recaptcha_site_key=os.getenv('RECAPTCHA_SITE_KEY',''))


@app.route('/dashboard')
@token_required # <-- RUTA PROTEGIDA
def dashboard(current_user):
    """Muestra el panel de control del usuario autenticado."""
    # current_user contiene el payload del JWT, incluyendo el 'sub' (ID de usuario)
    return render_template('dashboard.html', user_id=current_user.get('sub'))

# ===============================================
# NUEVA RUTA: LOGOUT 
# ===============================================

@app.route('/logout')
def logout():
    """Cierra la sesión del usuario borrando la cookie de autenticación."""
    flash('Has cerrado sesión correctamente.', 'info')
    resp = make_response(redirect(url_for('login')))
    # Borra la cookie de sesión de forma segura
    resp.set_cookie('access_token', '', expires=0, httponly=True, secure=True, samesite='Lax') 
    return resp

# ===============================================
# RUTAS DE RECUPERACIÓN DE CONTRASEÑA
# ===============================================

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection() # Uso corregido de la función
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE email=?', (email,))
        user_row = c.fetchone()
        conn.close()

        if user_row:
            user_id = user_row['id']
            # Generar token de restablecimiento (corta duración, HS256)
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
                flash(f'Error al enviar el correo. Revisa la configuración del servidor de correo. Error: {e}', 'danger')
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
        
        conn = get_db_connection() # Uso corregido de la función
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
@token_required 
def generate_pdf(current_user):
    """Genera un PDF simple en memoria y lo envía para ser descargado."""
    
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

@app.route('/sign_pdf', methods=['GET', 'POST'])
@token_required 
def sign_pdf_route(current_user):
    """Permite al usuario subir un PDF, calcular su hash y firmarlo con la clave privada RSA."""
    user_id = current_user.get('sub')
    
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
    
    try:
        # Leer archivo subido y calcular hash
        pdf_bytes = pdf_file.read()
        digest = hashlib.sha256(pdf_bytes).digest()
        
        # 1. Cargar clave privada
        if not PRIVATE_KEY:
            flash("Error: No existe la clave privada en keys/private.pem. Asegúrese de haber generado las claves (openssl).", 'danger')
            return redirect(url_for('sign_pdf_route'))

        private_key = load_pem_private_key(PRIVATE_KEY, password=None)
            
        # 2. Firmar el hash
        signature = private_key.sign(digest, padding.PKCS1v15(), hashes.SHA256())
        
        # 3. Guardar registro en la base de datos (documents_signatures)
        conn = get_db_connection()
        c = conn.cursor()
        document_name = secure_filename(pdf_file.filename)
        # Aquí se guardaría el path real si el archivo se subiera a disco o S3.
        # Por simplicidad, usamos un UUID como path de registro.
        document_path = f"sig_record_{uuid.uuid4().hex}" 
        
        c.execute('''
            INSERT INTO documents_signatures (document_name, document_path, user_id, signed_status, signed_at)
            VALUES (?, ?, ?, 1, datetime('now'))
        ''', (document_name, document_path, user_id))
        conn.commit()
        conn.close()

        # 4. Envía la firma generada en memoria al usuario
        sig_buffer = io.BytesIO(signature)
        sig_buffer.seek(0)
        
        flash('¡Documento firmado exitosamente! Descarga la firma y verifica su autenticidad.', 'success')
        return send_file(
            sig_buffer,
            as_attachment=True,
            download_name='signature_for_' + document_name + '.sig',
            mimetype='application/octet-stream'
        )
    
    except Exception as e:
        flash(f'Error al procesar la firma: {e}', 'danger')
        return redirect(url_for('sign_pdf_route'))


@app.route('/verify_signature', methods=['GET', 'POST'])
@token_required 
def verify_signature(current_user): 
    """Permite al usuario subir un PDF y un archivo de firma (.sig) para verificar su autenticidad con la clave pública."""
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
        
        try:
            # 2. Leer archivos y calcular hash del PDF
            pdf_bytes = pdf_file.read()
            sig_bytes = sig_file.read()
            digest = hashlib.sha256(pdf_bytes).digest()

            # 3. Cargar clave pública
            if not os.path.exists(JWT_PUBLIC_KEY_PATH):
                flash("Error: No se encontró la clave pública (keys/public.pem) en el servidor.", 'danger')
                return redirect(url_for('verify_signature'))

            with open(JWT_PUBLIC_KEY_PATH, 'rb') as kf:
                public_key = load_pem_public_key(kf.read())

            # 4. Verificar la firma
            public_key.verify(
                sig_bytes,
                digest,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            flash(' ¡Firma digital VERIFICADA! El documento es auténtico y no ha sido alterado.', 'success')
        except Exception as e:
            # Una verificación fallida lanzará una excepción (InvalidSignature), que manejamos aquí.
            flash(f' ¡Firma INVÁLIDA! El documento fue alterado o no fue firmado con nuestra clave. Error: {e}', 'danger')
        
        return redirect(url_for('verify_signature'))

    return render_template('verify_signature.html')


if __name__ == '__main__':
    # Usar 0.0.0.0 y puerto 5000 para compatibilidad con Render y entornos de producción
    app.run(host='0.0.0.0', port=5000, debug=True)

