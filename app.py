from flask import Flask, render_template, request, redirect, url_for, flash, make_response, send_file
import os, sqlite3, bcrypt, jwt, requests, hashlib, uuid
from datetime import datetime, timedelta
from models import DB, init_db
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change_me_securely')

DB_PATH = Path('database.db')
if not DB_PATH.exists():
    init_db()

def get_db_conn():
    return sqlite3.connect(DB)

# Cargar claves JWT
JWT_PRIVATE_KEY_PATH = os.getenv('JWT_PRIVATE_KEY_PATH', 'keys/private.pem')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM','RS256')
if Path(JWT_PRIVATE_KEY_PATH).exists():
    PRIVATE_KEY = open(JWT_PRIVATE_KEY_PATH,'rb').read()
else:
    PRIVATE_KEY = None

RECAPTCHA_SECRET = os.getenv('RECAPTCHA_SECRET')

def verify_captcha(token):
    if not RECAPTCHA_SECRET or RECAPTCHA_SECRET == 'put_secret_key_here':
        # Modo desarrollo: si no hay secret, aceptar (solo para pruebas locales)
        return True
    resp = requests.post('https://www.google.com/recaptcha/api/siteverify',
                         data={'secret': RECAPTCHA_SECRET, 'response': token})
    return resp.json().get('success', False)

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
        username = request.form['username'].strip()
        password = request.form['password'].encode('utf-8')
        captcha_token = request.form.get('g-recaptcha-response','')
        if not verify_captcha(captcha_token):
            flash('Captcha inválido','danger')
            return redirect(url_for('login'))
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
                token = jwt.encode(payload, 'dev-secret', algorithm='HS256')
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('access_token', token, httponly=True, secure=False, samesite='Lax')  # secure=True en HTTPS real
            return resp
        else:
            flash('Usuario o contraseña incorrecta','danger')
    return render_template('login.html', recaptcha_site_key=os.getenv('RECAPTCHA_SITE_KEY',''))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# Rutas simples para generar y descargar un PDF de ejemplo y su firma
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
    app.run(host='0.0.0.0', port=5000, debug=True)
