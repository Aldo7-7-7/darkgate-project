import sqlite3
import datetime
# Necesitarás instalar bcrypt: pip install bcrypt
import bcrypt

DB = 'database.db'
FACTORY_USER_EMAIL = 'test@darkgate.com'
FACTORY_PASSWORD = 'Password123!'

def get_db_connection():
    """Abre y retorna una conexión a la base de datos."""
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row # Permite acceder a las columnas por nombre
    return conn

def init_db():
    """Inicializa la base de datos, crea tablas e inserta el usuario de fábrica."""
    conn = get_db_connection()
    c = conn.cursor()

    # 1. Tabla de Usuarios
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            phone TEXT,
            created_at TEXT NOT NULL
        )
    ''')

    # 2. Tabla de Tokens de Reseteo (Para recuperación de contraseña)
    c.execute('''
        CREATE TABLE IF NOT EXISTS reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # 3. Nueva Tabla para la funcionalidad de firma de PDF (documents_signatures)
    # Se añade la tabla que pudo haber fallado antes por sintaxis, ahora corregida.
    c.execute('''
        CREATE TABLE IF NOT EXISTS documents_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_name TEXT NOT NULL,
            document_path TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            signed_status INTEGER NOT NULL DEFAULT 0, -- 0: Pendiente, 1: Firmado
            signed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # 4. Insertar Usuario de Fábrica (test@darkgate.com / Password123!)
    try:
        # Generar un hash válido para el usuario de fábrica usando bcrypt
        password_bytes = FACTORY_PASSWORD.encode('utf-8')
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')
        
        now = datetime.datetime.now().isoformat()
        
        # Intentar insertar el usuario
        c.execute('''
            INSERT INTO users (username, email, password_hash, phone, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', ('factory_user', FACTORY_USER_EMAIL, hashed_password, '555-1234', now))
        
        print(f"Usuario de fábrica insertado: {FACTORY_USER_EMAIL} / {FACTORY_PASSWORD}")
        
    except sqlite3.IntegrityError:
        # Esto ocurre si el usuario ya existe (debido a UNIQUE constraint en email/username)
        print(f"El usuario de fábrica {FACTORY_USER_EMAIL} ya existe. Saltando inserción.")
    except Exception as e:
        print(f"Error al insertar el usuario de fábrica: {e}")

    conn.commit()
    conn.close()

if __name__ == '__main__':
    # Inicializa la base de datos cada vez que se ejecuta este script.
    init_db()
    print("Base de datos inicializada o actualizada: database.db")
