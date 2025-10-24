import sqlite3

DB_FILE = "caller_id_manager.db"

def init_db():
    """Initialize the database and create tables if not exist."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password TEXT,
            role TEXT
        )
    ''')

    # Update logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS update_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT,
            caller_id TEXT,
            success BOOLEAN,
            reason TEXT,
            type TEXT,
            time TEXT
        )
    ''')

    conn.commit()
    conn.close()

def load_users_from_db():
    """Load all users from the database into a dictionary."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT email, password, role FROM users")
    users = {row[0]: {"password": row[1], "role": row[2]} for row in c.fetchall()}
    conn.close()
    return users

def save_user_to_db(email, password, role):
    """Insert or update a user in the database."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO users (email, password, role)
        VALUES (?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET
        password=excluded.password,
        role=excluded.role
    ''', (email, password, role))
    conn.commit()
    conn.close()

def delete_user_from_db(email):
    """Delete a user from the database."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE email = ?", (email,))
    conn.commit()
    conn.close()

# Initialize database at import
init_db()


