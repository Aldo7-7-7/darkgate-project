import sqlite3
DB = 'database.db'

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''
       CREATE TABLE IF NOT EXISTS users (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           username TEXT UNIQUE,
           email TEXT UNIQUE,
           password_hash TEXT,
           phone TEXT,
           created_at TEXT
       )
    ''')
    c.execute('''
       CREATE TABLE IF NOT EXISTS reset_tokens (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           user_id INTEGER,
           token TEXT,
           expires_at TEXT
       )
    ''')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("Base de datos inicializada: database.db")
