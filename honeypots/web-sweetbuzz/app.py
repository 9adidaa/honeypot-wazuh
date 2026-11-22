from flask import Flask, request, render_template_string, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'super_secret_honeypot_key'

DB_PATH = 'honeypot.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            is_admin INTEGER
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            comment TEXT
        )
    ''')
    cursor.execute("SELECT COUNT(*) FROM users WHERE username='admin'")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin', 'HoneyMaster2026!', 1)")
        cursor.execute("INSERT INTO users (username, password, is_admin) VALUES ('customer', 'sweettooth123', 0)")
    conn.commit()
    conn.close()

BASE_STYLE = """
<style>
    :root {
        --primary: #f5a623;
        --primary-dark: #d68910;
        --bg: #1a0f0a;
        --card-bg: #2c1810;
        --text: #fdf6e2;
        --text-muted: #d0c0a5;
    }
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background-color: var(--bg);
        color: var(--text);
        margin: 0;
        padding: 0;
    }
    header {
        background: linear-gradient(135deg, #2c1810, #3d2317);
        border-bottom: 3px solid var(--primary);
        padding: 20px 40px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    header h1 {
        margin: 0;
        color: var(--primary);
        font-size: 28px;
    }
    nav a {
        color: var(--text);
        text-decoration: none;
        margin-left: 20px;
        font-weight: 600;
        transition: color 0.3s;
    }
    nav a:hover {
        color: var(--primary);
    }
    .container {
        max-width: 1000px;
        margin: 40px auto;
        padding: 20px;
    }
    .card {
        background-color: var(--card-bg);
        border: 1px solid #4a2818;
        border-radius: 10px;
        padding: 30px;
        box-shadow: 0 8px 16px rgba(0,0,0,0.4);
        margin-bottom: 30px;
    }
    .btn {
        background-color: var(--primary);
        color: #1a0f0a;
        padding: 10px 20px;
        border: none;
        border-radius: 5px;
        font-weight: bold;
        cursor: pointer;
        transition: background 0.3s;
        text-decoration: none;
        display: inline-block;
    }
    .btn:hover {
        background-color: var(--primary-dark);
    }
    input[type="text"], input[type="password"], textarea {
        width: 100%;
        padding: 12px;
        margin: 8px 0 20px 0;
        border: 1px solid #4a2818;
        border-radius: 5px;
        background-color: #1f100b;
        color: var(--text);
        box-sizing: border-box;
    }
    .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 20px;
    }
    .product-card {
        background: var(--card-bg);
        border: 1px solid #4a2818;
        border-radius: 8px;
        padding: 20px;
        text-align: center;
    }
    .product-card h3 {
        color: var(--primary);
    }
    footer {
        text-align: center;
        padding: 20px;
        color: var(--text-muted);
        border-top: 1px solid #4a2818;
        margin-top: 50px;
    }
</style>
"""

@app.route('/')
def index():
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SweetBuzz Artisanal Honey</title>
        ''' + BASE_STYLE + '''
    </head>
    <body>
        <header>
            <h1>🐝 SweetBuzz Honey Co.</h1>
            <nav>
                <a href="/">Home</a>
                <a href="/login">Customer Login</a>
                <a href="/feedback">Customer Reviews</a>
                <a href="/admin" style="color: #ff6b6b;">Admin Portal</a>
            </nav>
        </header>
        <div class="container">
            <div class="card" style="text-align: center;">
                <h2>Pure, Raw & Golden Artisanal Honey</h2>
                <p>Harvested directly from sustainable family apiaries. Taste the golden difference of 100% natural, unfiltered honey.</p>
                <a href="/login" class="btn">Shop Member Deals</a>
            </div>
            
            <h2>Our Signature Collection</h2>
            <div class="grid">
                <div class="product-card">
                    <h3>Wildflower Gold</h3>
                    <p>Rich, floral notes harvested from mountain meadows.</p>
                    <p style="color: var(--primary); font-weight: bold;">$18.99 / jar</p>
                </div>
                <div class="product-card">
                    <h3>Acacia Blossom</h3>
                    <p>Light, delicate sweetness with a smooth finish.</p>
                    <p style="color: var(--primary); font-weight: bold;">$22.50 / jar</p>
                </div>
                <div class="product-card">
                    <h3>Manuka Reserve</h3>
                    <p>Premium grade raw honey with exceptional quality.</p>
                    <p style="color: var(--primary); font-weight: bold;">$45.00 / jar</p>
                </div>
            </div>
        </div>
        <footer>
            &copy; 2026 SweetBuzz Honey Co. All rights reserved. Secure Security Honey Pot Node.
        </footer>
    </body>
    </html>
    '''
    return render_template_string(html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # VULNERABLE SQL QUERY (SQLi)
        query = f"SELECT id, username, is_admin FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            if user:
                session['user'] = user[1]
                session['is_admin'] = user[3] if len(user) > 3 else 0
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid username or password!"
        except Exception as e:
            error = f"Database Error: {e}"
        conn.close()
        
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Customer Login - SweetBuzz</title>
        ''' + BASE_STYLE + '''
    </head>
    <body>
        <header>
            <h1>🐝 SweetBuzz Honey Co.</h1>
            <nav>
                <a href="/">Home</a>
                <a href="/login">Customer Login</a>
                <a href="/feedback">Customer Reviews</a>
                <a href="/admin" style="color: #ff6b6b;">Admin Portal</a>
            </nav>
        </header>
        <div class="container" style="max-width: 500px;">
            <div class="card">
                <h2>Customer Portal Login</h2>
                {% if error %}<p style="color: #ff6b6b; font-weight: bold;">{{ error }}</p>{% endif %}
                <form method="POST">
                    <label>Username:</label>
                    <input type="text" name="username" required>
                    <label>Password:</label>
                    <input type="password" name="password" required>
                    <button type="submit" class="btn" style="width: 100%;">Sign In</button>
                </form>
            </div>
        </div>
        <footer>&copy; 2026 SweetBuzz Honey Co.</footer>
    </body>
    </html>
    '''
    return render_template_string(html, error=error)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Member Dashboard - SweetBuzz</title>
        ''' + BASE_STYLE + '''
    </head>
    <body>
        <header>
            <h1>🐝 SweetBuzz Honey Co.</h1>
            <nav>
                <a href="/">Home</a>
                <a href="/feedback">Customer Reviews</a>
                <a href="/logout">Logout</a>
            </nav>
        </header>
        <div class="container">
            <div class="card">
                <h2>Welcome back, {{ user }}!</h2>
                <p>Thank you for being a valued member of our honey lovers community.</p>
                <div style="background: #3d2317; padding: 15px; border-radius: 5px; border-left: 4px solid var(--primary); margin: 20px 0;">
                    <h3 style="margin-top: 0; color: var(--primary);">Exclusive VIP Reward</h3>
                    <p>Secret Flag: <code>CODEBY{HONEYPOT_SQLI_BYPASS_SUCCESS}</code></p>
                </div>
                <a href="/feedback" class="btn">View Customer Reviews</a>
            </div>
        </div>
        <footer>&copy; 2026 SweetBuzz Honey Co.</footer>
    </body>
    </html>
    '''
    return render_template_string(html, user=session['user'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST', 'PUT', 'DELETE'])
def admin():
    if request.method == 'GET':
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Portal - SweetBuzz</title>
            ''' + BASE_STYLE + '''
        </head>
        <body>
            <header>
                <h1>🐝 SweetBuzz Honey Co. - Admin</h1>
                <nav>
                    <a href="/">Home</a>
                </nav>
            </header>
            <div class="container" style="max-width: 500px;">
                <div class="card" style="border-color: #8b0000;">
                    <h2 style="color: #ff6b6b;">Restricted Management Portal</h2>
                    <p>Authorized personnel only. All access attempts are logged and monitored by SIEM.</p>
                    <form method="POST">
                        <label>Admin Password:</label>
                        <input type="password" name="password" required>
                        <button type="submit" class="btn" style="width: 100%; background-color: #ff6b6b; color: #fff;">Authenticate</button>
                    </form>
                </div>
            </div>
            <footer>&copy; 2026 SweetBuzz Honey Co.</footer>
        </body>
        </html>
        '''
        return render_template_string(html)
    elif request.method == 'POST':
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Access Denied</title>
            ''' + BASE_STYLE + '''
        </head>
        <body>
            <div class="container" style="max-width: 600px; text-align: center;">
                <div class="card" style="border-color: #8b0000;">
                    <h1 style="color: #ff6b6b;">Access Denied: Invalid Credentials!</h1>
                    <p>This unauthorized access attempt has been recorded and reported to security operations.</p>
                    <a href="/admin" class="btn" style="margin-top: 20px;">Back to Login</a>
                </div>
            </div>
        </body>
        </html>
        '''
        return render_template_string(html), 403
    elif request.method == 'DELETE':
        return "<h1>Admin Authorization Bypassed. Flag: CODEBY{METHOD_TAMPERING_MASTER}</h1>"
    else:
        return "Method Not Allowed", 405

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if request.method == 'POST':
        name = request.form.get('name', 'Anonymous')
        comment = request.form.get('comment', '')
        cursor.execute("INSERT INTO feedback (name, comment) VALUES (?, ?)", (name, comment))
        conn.commit()
    
    cursor.execute("SELECT name, comment FROM feedback")
    feedbacks = cursor.fetchall()
    conn.close()

    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Customer Reviews - SweetBuzz</title>
        ''' + BASE_STYLE + '''
    </head>
    <body>
        <header>
            <h1>🐝 SweetBuzz Honey Co.</h1>
            <nav>
                <a href="/">Home</a>
                <a href="/login">Customer Login</a>
                <a href="/feedback">Customer Reviews</a>
            </nav>
        </header>
        <div class="container">
            <div class="card">
                <h2>Leave a Customer Review</h2>
                <form method="POST">
                    <label>Your Name:</label>
                    <input type="text" name="name" required>
                    <label>Review / Comments (HTML supported):</label>
                    <textarea name="comment" rows="4" required></textarea>
                    <button type="submit" class="btn">Submit Review</button>
                </form>
            </div>
            
            <h2>What Our Honey Lovers Say</h2>
            {% for f in feedbacks %}
                <div class="card" style="padding: 20px; margin-bottom: 15px;">
                    <h4 style="margin: 0 0 10px 0; color: var(--primary);">{{ f[0] }}</h4>
                    <!-- VULNERABLE: Stored XSS via |safe -->
                    <p style="margin: 0;">{{ f[1]|safe }}</p>
                </div>
            {% endfor %}
        </div>
        <footer>&copy; 2026 SweetBuzz Honey Co.</footer>
    </body>
    </html>
    '''
    return render_template_string(html, feedbacks=feedbacks)

# === Wazuh honeypot access logging (live capture) ===
import re as _re
from urllib.parse import unquote_plus as _uq
_ACCESS_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "access.log")

def _field(s, n=1200):
    s = _re.sub(r"[^\x20-\x7e]", "?", str(s))
    s = _re.sub(r"\s+", " ", s).strip()
    s = s.replace('%', '%25').replace(' ', '+').replace('"', '%22')
    return s[:n]

@app.after_request
def _hp_access_log(resp):
    try:
        # src = real TCP peer (not spoofable); X-Forwarded-For is attacker-controlled,
        # so it is only logged for information in its own field
        src = request.remote_addr or "-"
        xff = request.headers.get("X-Forwarded-For", "")
        q = request.query_string.decode("utf-8", "replace")
        body = ""
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            try:
                if request.form:
                    body = "&".join("%s=%s" % (k, v) for k, v in request.form.items())
                else:
                    body = request.get_data(cache=True, as_text=True)[:1500] or ""
            except Exception:
                body = ""
        path = request.path + ("?" + q if q else "")
        payload = body if body else q
        # decode once so detection rules see plaintext keywords, then re-encode safely
        plain = _uq(str(payload))
        line = (
            "HONEYPOT-ACCESS src=%s method=%s path=%s status=%d body=%s ua=%s xff=%s\n"
            % (src, request.method, _field(path),
               resp.status_code, _field(plain) or "-", _field(request.user_agent.string, 200) or "-",
               _field(xff, 200) or "-")
        )
        os.makedirs(os.path.dirname(_ACCESS_LOG), exist_ok=True)
        with open(_ACCESS_LOG, "a") as _f:
            _f.write(line)
    except Exception as _e:
        try:
            os.makedirs(os.path.dirname(_ACCESS_LOG), exist_ok=True)
            with open(_ACCESS_LOG + ".err", "a") as _ef:
                _ef.write("ERR %r\n" % (_e,))
        except Exception:
            pass
    return resp


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)

