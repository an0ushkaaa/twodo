from dotenv import load_dotenv
load_dotenv()

import os
import psycopg2
import psycopg2.extras
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

# ─────────────────────────────────────────
# CONFIG — reads from environment variables
# Locally:    put these in a .env file
# On Render:  set them in the dashboard
# ─────────────────────────────────────────

app.secret_key = os.environ.get('SECRET_KEY', 'dev-fallback-change-this')
DATABASE_URL   = os.environ.get('DATABASE_URL', '')
print("DEBUG DATABASE_URL:", DATABASE_URL)


# Render gives Postgres URLs starting with "postgres://"
# but psycopg2 needs "postgresql://" — fix it automatically
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)


# ─────────────────────────────────────────
# DATABASE HELPERS
# ─────────────────────────────────────────

def get_db():
    """
    Open and return a PostgreSQL connection + cursor.
    RealDictCursor means rows behave like dictionaries,
    so row['username'] works just like it did with SQLite.
    """
    conn   = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    return conn, cursor


def init_db():
    """
    Create all tables if they don't exist.
    Called automatically every time the app starts —
    CREATE TABLE IF NOT EXISTS makes this safe.
    """
    conn, cur = get_db()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id           SERIAL PRIMARY KEY,
            username     TEXT UNIQUE NOT NULL,
            password     TEXT NOT NULL,
            display_name TEXT NOT NULL,
            partner_id   INTEGER
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS todos (
            id         SERIAL PRIMARY KEY,
            user_id    INTEGER NOT NULL REFERENCES users(id),
            text       TEXT NOT NULL,
            done       INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS moods (
            id         SERIAL PRIMARY KEY,
            user_id    INTEGER NOT NULL REFERENCES users(id),
            score      INTEGER NOT NULL,
            note       TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id         SERIAL PRIMARY KEY,
            from_user  INTEGER NOT NULL REFERENCES users(id),
            to_user    INTEGER NOT NULL REFERENCES users(id),
            message    TEXT NOT NULL,
            read       INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS date_ideas (
            id         SERIAL PRIMARY KEY,
            added_by   INTEGER NOT NULL REFERENCES users(id),
            idea       TEXT NOT NULL,
            done       INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()


# ─────────────────────────────────────────
# AUTH HELPERS
# ─────────────────────────────────────────

def login_required(f):
    """Redirect to /login if the user is not logged in."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def current_user():
    """Return the logged-in user's row from the database."""
    if 'user_id' not in session:
        return None
    conn, cur = get_db()
    cur.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user


def get_partner(user):
    """Return the partner's row, or None if not linked."""
    if not user or not user['partner_id']:
        return None
    conn, cur = get_db()
    cur.execute('SELECT * FROM users WHERE id = %s', (user['partner_id'],))
    partner = cur.fetchone()
    cur.close()
    conn.close()
    return partner


# ─────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']

        conn, cur = get_db()
        cur.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        # check_password_hash safely compares the submitted
        # password against the stored hash
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        else:
            flash('Wrong username or password 💔', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username     = request.form['username'].strip().lower()
        display_name = request.form['display_name'].strip()
        # Hash the password — the real password is NEVER stored
        password     = generate_password_hash(request.form['password'])

        conn, cur = get_db()
        try:
            cur.execute(
                'INSERT INTO users (username, password, display_name) VALUES (%s, %s, %s)',
                (username, password, display_name)
            )
            conn.commit()
            flash('Account created! Log in now 🎉', 'success')
            return redirect(url_for('login'))
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            flash('That username is taken 😬', 'error')
        finally:
            cur.close()
            conn.close()

    return render_template('register.html')


@app.route('/link-partner', methods=['GET', 'POST'])
@login_required
def link_partner():
    user = current_user()
    if request.method == 'POST':
        partner_username = request.form['partner_username'].strip().lower()
        conn, cur = get_db()
        cur.execute('SELECT * FROM users WHERE username = %s', (partner_username,))
        partner = cur.fetchone()

        if not partner:
            flash("Couldn't find that user 🤔", 'error')
        elif partner['id'] == user['id']:
            flash("That's you! Enter your partner's username 😄", 'error')
        else:
            cur.execute('UPDATE users SET partner_id = %s WHERE id = %s',
                        (partner['id'], user['id']))
            cur.execute('UPDATE users SET partner_id = %s WHERE id = %s',
                        (user['id'], partner['id']))
            conn.commit()
            flash(f"Linked with {partner['display_name']}! 💕", 'success')
            cur.close()
            conn.close()
            return redirect(url_for('dashboard'))

        cur.close()
        conn.close()

    return render_template('link_partner.html', user=user)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ─────────────────────────────────────────
# MAIN DASHBOARD
# ─────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    user      = current_user()
    partner   = get_partner(user)
    conn, cur = get_db()

    cur.execute(
        'SELECT * FROM todos WHERE user_id = %s ORDER BY done ASC, created_at DESC',
        (user['id'],)
    )
    my_todos = cur.fetchall()

    partner_todos = []
    if partner:
        cur.execute(
            'SELECT * FROM todos WHERE user_id = %s ORDER BY done ASC, created_at DESC',
            (partner['id'],)
        )
        partner_todos = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('dashboard.html',
        user=user,
        partner=partner,
        my_todos=my_todos,
        partner_todos=partner_todos,
    )



# ─────────────────────────────────────────
# TODO ROUTES
# ─────────────────────────────────────────

@app.route('/todo/add', methods=['POST'])
@login_required
def add_todo():
    text = request.form['text'].strip()
    if text:
        conn, cur = get_db()
        cur.execute('INSERT INTO todos (user_id, text) VALUES (%s, %s)',
                    (session['user_id'], text))
        conn.commit()
        cur.close()
        conn.close()
    return redirect(url_for('dashboard'))


@app.route('/todo/toggle/<int:todo_id>')
@login_required
def toggle_todo(todo_id):
    conn, cur = get_db()
    cur.execute('SELECT * FROM todos WHERE id = %s', (todo_id,))
    todo = cur.fetchone()
    if todo and todo['user_id'] == session['user_id']:
        new_state = 0 if todo['done'] else 1
        cur.execute('UPDATE todos SET done = %s WHERE id = %s', (new_state, todo_id))
        conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('dashboard'))


@app.route('/todo/delete/<int:todo_id>')
@login_required
def delete_todo(todo_id):
    conn, cur = get_db()
    cur.execute('DELETE FROM todos WHERE id = %s AND user_id = %s',
                (todo_id, session['user_id']))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('dashboard'))


# ─────────────────────────────────────────
# MOOD ROUTES
# ─────────────────────────────────────────

@app.route('/mood/log', methods=['POST'])
@login_required
def log_mood():
    score     = int(request.form['score'])
    note      = request.form.get('note', '').strip()
    conn, cur = get_db()
    cur.execute(
        'INSERT INTO moods (user_id, score, note) VALUES (%s, %s, %s)',
        (session['user_id'], score, note)
    )
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('dashboard'))


# ─────────────────────────────────────────
# NOTES ROUTES
# ─────────────────────────────────────────

@app.route('/notes')
@login_required
def notes():
    user      = current_user()
    partner   = get_partner(user)
    conn, cur = get_db()

    cur.execute('UPDATE notes SET read = 1 WHERE to_user = %s', (user['id'],))
    conn.commit()

    cur.execute(
        '''SELECT notes.*,
                  u1.display_name AS sender_name,
                  u2.display_name AS receiver_name
           FROM notes
           JOIN users u1 ON notes.from_user = u1.id
           JOIN users u2 ON notes.to_user   = u2.id
           WHERE notes.from_user = %s OR notes.to_user = %s
           ORDER BY notes.created_at DESC''',
        (user['id'], user['id'])
    )
    all_notes = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('notes.html', user=user, partner=partner, notes=all_notes)


@app.route('/notes/send', methods=['POST'])
@login_required
def send_note():
    user    = current_user()
    partner = get_partner(user)
    message = request.form['message'].strip()

    if message and partner:
        conn, cur = get_db()
        cur.execute(
            'INSERT INTO notes (from_user, to_user, message) VALUES (%s, %s, %s)',
            (user['id'], partner['id'], message)
        )
        conn.commit()
        cur.close()
        conn.close()
        flash('Note sent 💌', 'success')

    return redirect(url_for('notes'))




# ─────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────





if __name__ == '__main__':
    app.run()
