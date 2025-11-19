from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_PATH = 'jobs.db'


# ---------------------- Database ----------------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            banned INTEGER DEFAULT 0
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            company TEXT NOT NULL,
            description TEXT NOT NULL,
            owner_id INTEGER,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()


init_db()


# ---------------------- Decorators ----------------------
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()

        if not user:
            session.clear()
            flash('User not found. Please log in again.', 'danger')
            return redirect(url_for('login'))

        if user['banned'] == 1:
            session.clear()
            flash('Your account is banned.', 'danger')
            return redirect(url_for('login'))

        return f(*args, **kwargs)

    return wrapped


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if session.get('role') not in roles:
                flash('You do not have permission to access that page.', 'danger')

                if session.get('role') == 'admin':
                    return redirect(url_for('admin_users'))
                return redirect(url_for('posts'))

            return f(*args, **kwargs)

        return wrapped

    return decorator


# ---------------------- Landing / Home ----------------------
@app.route('/')
def home():
    """Homepage — not logged in = show home.html"""
    if 'user_id' in session:
        if session['role'] == 'admin':
            return redirect(url_for('admin_users'))
        return redirect(url_for('posts'))
    return render_template('home.html')


# ---------------------- Auth ----------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        role = request.form['role']

        if role not in ('admin', 'employee', 'recruiter'):
            flash('Invalid role selected.', 'danger')
            return redirect(url_for('register'))

        if not username or not password:
            flash('Username and password required.', 'warning')
            return redirect(url_for('register'))

        pw_hash = generate_password_hash(password)

        try:
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                (username, pw_hash, role)
            )
            conn.commit()
            conn.close()

            # Auto-login after register
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            conn.close()

            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']

            if user['role'] in ('employee', 'recruiter'):
                return redirect(url_for('posts'))
            return redirect(url_for('admin_users'))

        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if not user or not check_password_hash(user['password_hash'], password):
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

        if user['banned']:
            flash('Your account is banned.', 'danger')
            return redirect(url_for('login'))

        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']

        if user['role'] == 'admin':
            return redirect(url_for('admin_users'))
        return redirect(url_for('posts'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('home'))


# ---------------------- Job Posts ----------------------
@app.route('/posts')
@login_required
@role_required('employee', 'recruiter', 'admin')
def posts():
    conn = get_db_connection()
    jobs = conn.execute('''
        SELECT jobs.*, users.username AS owner_name
        FROM jobs
        LEFT JOIN users ON users.id = jobs.owner_id
        ORDER BY jobs.id DESC
    ''').fetchall()
    conn.close()

    return render_template('posts.html', jobs=jobs)


@app.route('/post/create', methods=['GET', 'POST'])
@login_required
@role_required('employee', 'recruiter')
def create_post():
    if request.method == 'POST':
        title = request.form['title'].strip()
        company = request.form['company'].strip()
        description = request.form['description'].strip()

        if not title or not company or not description:
            flash('All fields are required.', 'warning')
            return redirect(url_for('create_post'))

        conn = get_db_connection()
        conn.execute('INSERT INTO jobs (title, company, description, owner_id) VALUES (?, ?, ?, ?)',
                     (title, company, description, session['user_id']))
        conn.commit()
        conn.close()

        flash('Job posted successfully.', 'success')
        return redirect(url_for('posts'))

    return render_template('create_edit_post.html', action='Create')


@app.route('/post/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
@role_required('employee', 'recruiter', 'admin')
def edit_post(post_id):
    conn = get_db_connection()
    job = conn.execute('SELECT * FROM jobs WHERE id = ?', (post_id,)).fetchone()
    conn.close()

    if not job:
        flash('Post not found.', 'danger')
        return redirect(url_for('posts'))

    if session['role'] != 'admin' and job['owner_id'] != session['user_id']:
        flash('You are not allowed to edit this post.', 'danger')
        return redirect(url_for('posts'))

    if request.method == 'POST':
        title = request.form['title']
        company = request.form['company']
        description = request.form['description']

        conn = get_db_connection()
        conn.execute('UPDATE jobs SET title=?, company=?, description=? WHERE id=?',
                     (title, company, description, post_id))
        conn.commit()
        conn.close()

        flash('Post updated.', 'success')
        return redirect(url_for('posts'))

    return render_template('create_edit_post.html', action='Edit', job=job)


@app.route('/post/delete/<int:post_id>', methods=['POST'])
@login_required
@role_required('employee', 'recruiter', 'admin')
def delete_post(post_id):
    conn = get_db_connection()
    job = conn.execute('SELECT * FROM jobs WHERE id = ?', (post_id,)).fetchone()

    if not job:
        conn.close()
        flash('Post not found.', 'danger')
        return redirect(url_for('posts'))

    if session['role'] != 'admin' and job['owner_id'] != session['user_id']:
        conn.close()
        flash('You are not allowed to delete this.', 'danger')
        return redirect(url_for('posts'))

    conn.execute('DELETE FROM jobs WHERE id = ?', (post_id,))
    conn.commit()
    conn.close()

    flash('Post deleted.', 'success')
    return redirect(url_for('posts'))


# ---------------------- Admin ----------------------
@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, role, banned FROM users ORDER BY id ASC').fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)


@app.route('/admin/ban/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def ban_user(user_id):
    if user_id == session['user_id']:
        flash("You cannot ban yourself.", "warning")
        return redirect(url_for('admin_users'))

    conn = get_db_connection()
    conn.execute('UPDATE users SET banned = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('User banned.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/unban/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def unban_user(user_id):
    conn = get_db_connection()
    conn.execute('UPDATE users SET banned = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('User unbanned.', 'success')
    return redirect(url_for('admin_users'))


# ---------------------- My Posts ----------------------
@app.route('/my/posts')
@login_required
def my_posts():
    conn = get_db_connection()
    jobs = conn.execute('SELECT * FROM jobs WHERE owner_id = ? ORDER BY id DESC', (session['user_id'],)).fetchall()
    conn.close()

    return render_template('my_posts.html', jobs=jobs)


# ---------------------- Run ----------------------
if __name__ == '__main__':
    app.run(debug=True)
