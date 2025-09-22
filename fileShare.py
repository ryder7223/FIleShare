import subprocess
import importlib
import sys
import threading
import time

required_modules = ['colorama', 'itsdangerous', 'click', 'blinker', 'flask']

def install_missing_modules(modules):
    try:
        pip = 'pip'
        importlib.import_module(pip)
    except ImportError:
        print(f"{pip} is not installed. Installing...")
        subprocess.check_call([sys.executable, "-m", "ensurepip", "--upgrade"])
    for module in modules:
        try:
            importlib.import_module(module)
        except ImportError:
            print(f"{module} is not installed. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])

install_missing_modules(required_modules)

import os
import json
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session
from flask import Flask, request, redirect, url_for, send_from_directory, render_template_string, flash, jsonify
from werkzeug.utils import secure_filename

from functools import wraps

# Configuration
UPLOAD_FOLDER = './uploads'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'supersecretkey'  # Needed for flashing messages

# Create the upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# HTML template for the webpage
HTML = '''
<!doctype html>
<html>
  <head>
    <title>Local File Sharing</title>
    <style>
      body { font-family: Arial, sans-serif; text-align: center; margin: 20px; }
      .progress-container { width: 50%; margin: 20px auto; display: none; }
      .progress-bar { width: 100%; background-color: #f3f3f3; border: 1px solid #ccc; }
      .progress { height: 20px; width: 0%; background-color: #4caf50; text-align: center; color: white; line-height: 20px; }
    </style>
  </head>
  <body>
    <h1>Upload a File</h1>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul>
        {% for message in messages %}
          <li>{{ message }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}
    
    <form id="uploadForm">
      <input type="file" id="fileInput" name="file">
      <label><input type="checkbox" id="temporary" name="temporary"> Temporary</label>
      <input type="number" id="expiry_hours" name="expiry_hours" min="1" max="168" placeholder="Expiry (hours)">
      <button type="button" onclick="uploadFile()">Upload</button>
    </form>

    <div class="progress-container">
      <div class="progress-bar">
        <div id="progress" class="progress">0%</div>
      </div>
    </div>

    <h2>Available Files</h2>
    <form method="get" style="margin-bottom: 10px;">
      <input type="text" name="q" placeholder="Search files" value="{{ request.args.get('q', '') }}">
      <select name="sort">
        <option value="name" {% if sort == 'name' %}selected{% endif %}>Name</option>
        <option value="date" {% if sort == 'date' %}selected{% endif %}>Upload Date</option>
        <option value="size" {% if sort == 'size' %}selected{% endif %}>Size</option>
        <option value="downloads" {% if sort == 'downloads' %}selected{% endif %}>Downloads</option>
      </select>
      <select name="order">
        <option value="asc" {% if order == 'asc' %}selected{% endif %}>Ascending</option>
        <option value="desc" {% if order == 'desc' %}selected{% endif %}>Descending</option>
      </select>
      <button type="submit">Apply</button>
    </form>
    <ul>
      {% for file in files %}
        <li>
          <a href="{{ url_for('download_file', filename=file['name']) }}">{{ file['name'] }}</a>
          ({{ file['size']|default(0, true) // 1024 }} KB, {{ file['download_count']|default(0, true) }} downloads)
          {% if file['temporary'] %} [Temporary]{% endif %}
          {% if file['expiry'] %} [Expires: {{ file['expiry'][:16].replace('T', ' ') }}]{% endif %}
          {% if file['uploader'] == session['username'] or is_admin %}
            <form method="post" action="{{ url_for('delete_file', filename=file['name']) }}" style="display:inline;">
              <button type="submit">Delete</button>
            </form>
          {% endif %}
        </li>
      {% endfor %}
    </ul>

    <script>
      function uploadFile() {
          let fileInput = document.getElementById('fileInput');
          if (!fileInput.files.length) {
              alert("Please select a file.");
              return;
          }

          let file = fileInput.files[0];
          let formData = new FormData();
          formData.append("file", file);
          let temporary = document.getElementById('temporary').checked;
          let expiry_hours = document.getElementById('expiry_hours').value;
          formData.append("temporary", temporary ? '1' : '0');
          formData.append("expiry_hours", expiry_hours);

          let xhr = new XMLHttpRequest();
          xhr.open("POST", "/", true);

          // Show progress bar
          document.querySelector('.progress-container').style.display = "block";

          xhr.upload.onprogress = function(event) {
              if (event.lengthComputable) {
                  let percentComplete = (event.loaded / event.total) * 100;
                  let progressBar = document.getElementById('progress');
                  progressBar.style.width = percentComplete + "%";
                  progressBar.innerText = Math.round(percentComplete) + "%";
              }
          };

          xhr.onload = function() {
              if (xhr.status == 200) {
                  location.reload();  // Refresh to show new file
              } else {
                  alert("File upload failed.");
              }
          };

          xhr.send(formData);
      }
    </script>
  </body>
</html>
'''

# --- User Management ---
USERS_FILE = 'users.txt'
PRIV_USER = '0'
PRIV_ADMIN = '1'
PRIV_SUPERUSER = '2'

def load_users():
    users = {}
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if ':' in line:
                    parts = line.strip().split(':')
                    if len(parts) >= 3:
                        username = parts[0]
                        priv = parts[-1]
                        pw_hash = ':'.join(parts[1:-1])
                    elif len(parts) == 2:
                        username, pw_hash = parts
                        priv = PRIV_USER
                    else:
                        continue
                    users[username] = (pw_hash, priv)
    return users

def save_user(username, password, priv=PRIV_USER):
    pw_hash = generate_password_hash(password)
    with open(USERS_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{username}:{pw_hash}:{priv}\n")

def is_superuser():
    users = load_users()
    if 'username' not in session:
        return False
    username = session['username']
    return username in users and users[username][1] == PRIV_SUPERUSER

def is_admin():
    users = load_users()
    if 'username' not in session:
        return False
    username = session['username']
    return username in users and users[username][1] in (PRIV_ADMIN, PRIV_SUPERUSER)

def check_session_password():
    if 'username' not in session or 'pw_hash' not in session:
        return False
    users = load_users()
    username = session['username']
    if username not in users:
        return False
    return session['pw_hash'] == users[username][0]

# --- Registration, Login, Logout Routes ---
registration_template = """
<!doctype html>
<title>Register</title>
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul>
    {% for msg in messages %}
      <li>{{ msg }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
<h2>Register a new account:</h2>
<form method="post" action="{{ url_for('register') }}">
  <input type="text" name="username" required placeholder="Username">
  <input type="password" name="password" required placeholder="Password">
  <input type="submit" value="Register">
</form>
<p>Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
"""

login_template = """
<!doctype html>
<title>Login</title>
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul>
    {% for msg in messages %}
      <li>{{ msg }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
<h2>Login to your account:</h2>
<form method="post" action="{{ url_for('login') }}">
  <input type="text" name="username" required placeholder="Username">
  <input type="password" name="password" required placeholder="Password">
  <input type="submit" value="Login">
</form>
<p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a></p>
"""

# --- Per-user folder helpers ---
def get_user_folder(username):
    return os.path.join(UPLOAD_FOLDER, username)

def ensure_user_folder(username):
    folder = get_user_folder(username)
    if not os.path.exists(folder):
        os.makedirs(folder)

# Update registration to create user folder
'''
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            flash("Username and password cannot be empty.")
            return redirect(url_for('register'))
        users = load_users()
        if username in users:
            flash("Username already exists. Please choose another.")
            return redirect(url_for('register'))
        save_user(username, password, priv=PRIV_USER)
        ensure_user_folder(username)
        flash("Registration successful! Please log in.")
        return redirect(url_for('login'))
    return render_template_string(registration_template)
'''
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            flash("Username and password cannot be empty.")
            return redirect(url_for('register'))
        
        users = load_users()
        if username in users:
            flash("Username already exists. Please choose another.")
            return redirect(url_for('register'))
        
        # Assign admin privileges if username is "User"
        priv = PRIV_SUPERUSER if username == "User" else PRIV_USER
        save_user(username, password, priv=priv)
        ensure_user_folder(username)
        flash("Registration successful! Please log in.")
        return redirect(url_for('login'))
    
    return render_template_string(registration_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    users = load_users()
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            flash("Username and password cannot be empty.")
            return redirect(url_for('login'))
        if username not in users or not check_password_hash(users[username][0], password):
            flash("Invalid username or password.")
            return redirect(url_for('login'))
        session['username'] = username
        session['pw_hash'] = users[username][0]
        return redirect(url_for('user_folder', username=username))
    return render_template_string(login_template)

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('username', None)
    session.pop('pw_hash', None)
    flash('Logged out successfully.')
    return redirect(url_for('login'))

# --- File Metadata and Quotas ---
FILE_STATS = 'file_stats.json'
USER_QUOTAS = 'user_quotas.json'
MAX_UPLOAD_SIZE_FILE = 'max_upload_size.txt'
DEFAULT_MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
DEFAULT_USER_QUOTA = 50 * 1024 * 1024  # 50 MB
DEFAULT_ADMIN_QUOTA = 2 * 1024 * 1024 * 1024  # 2 GB
DEFAULT_SUPERUSER_QUOTA = 10 * 1024 * 1024 * 1024  # 10 GB

# Ensure metadata files exist
for fname, default in [
    (FILE_STATS, {}),
    (USER_QUOTAS, {}),
]:
    if not os.path.exists(fname):
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump(default, f)
if not os.path.exists(MAX_UPLOAD_SIZE_FILE):
    with open(MAX_UPLOAD_SIZE_FILE, 'w', encoding='utf-8') as f:
        f.write(str(DEFAULT_MAX_UPLOAD_SIZE))

FILE_EVENTS_LOG = 'file_events.log'

def log_file_event(event_type, filename, user, ip, extra=None):
    with open(FILE_EVENTS_LOG, 'a', encoding='utf-8') as f:
        entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'event': event_type,
            'filename': filename,
            'user': user,
            'ip': ip,
            'extra': extra
        }
        f.write(json.dumps(entry) + '\n')

def cleanup_expired_files():
    stats = load_file_stats()
    now = datetime.datetime.now()
    to_delete = []
    users = list(load_users().keys())
    for fname, meta in stats.items():
        if meta.get('temporary') and meta.get('expiry'):
            try:
                expiry = datetime.datetime.fromisoformat(meta['expiry'])
                if now > expiry:
                    to_delete.append((fname, meta.get('uploader')))
            except Exception:
                continue
    for fname, uploader in to_delete:
        folder = get_user_folder(uploader) if uploader else UPLOAD_FOLDER
        try:
            os.remove(os.path.join(folder, fname))
        except Exception:
            pass
        remove_file_metadata(fname)
        log_file_event('expired_delete', fname, 'system', 'localhost')

def with_expiry_cleanup(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        cleanup_expired_files()
        return f(*args, **kwargs)
    return decorated

def binary_filesize(value):
    # value is bytes
    units = ["bytes", "KiB", "MiB", "GiB", "TiB"]
    size = float(value)
    i = 0
    while size >= 1024 and i < len(units) - 1:
        size /= 1024.0
        i += 1
    return f"{size:.2f} {units[i]}"

app.jinja_env.filters['binary_filesize'] = binary_filesize

# Main page: list all user folders
main_template = '''
<!doctype html>
<title>File Share - User Folders</title>
<h1>User Folders</h1>
<ul>
  {% for user in users %}
    <li><a href="{{ url_for('user_folder', username=user) }}">{{ user }}</a></li>
  {% endfor %}
</ul>
<p><a href="/logout">Logout</a>{% if is_admin %} | <a href="/admin">Admin</a>{% endif %}</p>
'''

@app.route('/')
@with_expiry_cleanup
def main():
    if 'username' not in session:
        return redirect(url_for('login'))
    users = list(load_users().keys())
    return render_template_string(main_template, users=users, is_admin=is_admin())

# User folder page: list files, allow upload/delete if owner
user_folder_template = '''
<!doctype html>
<title>Files for {{ username }}</title>
<h1>Files for {{ username }}</h1>
<script>
var MAX_UPLOAD_SIZE = {{ max_upload_size }};
var USER_QUOTA = {{ user_quota }};
var USER_USED = {{ user_used }};
</script>
<div style="width:60%;margin:10px auto 20px auto;">
  <div style="text-align:left;">Storage used: {{ user_used|binary_filesize }} / {{ user_quota|binary_filesize }} ({{ (100*user_used/user_quota)|round(1) }}%)</div>
  <div style="background:#eee;border:1px solid #aaa;height:22px;width:100%;border-radius:6px;overflow:hidden;">
    <div style="background:#4caf50;height:100%;width:{{ (100*user_used/user_quota)|round(1) }}%;color:white;text-align:center;line-height:22px;">{{ (100*user_used/user_quota)|round(1) }}%</div>
  </div>
</div>
{% if can_upload %}
<form id="uploadForm">
  <input type="file" id="fileInput" name="file">
  <label><input type="checkbox" id="temporary" name="temporary"> Temporary</label>
  <input type="number" id="expiry_seconds" name="expiry_seconds" min="0" placeholder="Seconds" style="width:70px;">
  <input type="number" id="expiry_minutes" name="expiry_minutes" min="0" placeholder="Minutes" style="width:70px;">
  <input type="number" id="expiry_hours" name="expiry_hours" min="0" placeholder="Hours" style="width:70px;">
  <input type="number" id="expiry_days" name="expiry_days" min="0" placeholder="Days" style="width:70px;">
  <input type="number" id="expiry_weeks" name="expiry_weeks" min="0" placeholder="Weeks" style="width:70px;">
  <input type="number" id="expiry_months" name="expiry_months" min="0" placeholder="Months" style="width:70px;">
  <input type="number" id="expiry_years" name="expiry_years" min="0" placeholder="Years" style="width:70px;">
  <button type="button" onclick="uploadFile()">Upload</button>
</form>
<div class="progress-container" style="width:50%;margin:20px auto;display:none;">
  <div class="progress-bar" style="width:100%;background-color:#f3f3f3;border:1px solid #ccc;">
    <div id="progress" class="progress" style="height:20px;width:0%;background-color:#4caf50;text-align:center;color:white;line-height:20px;">0%</div>
  </div>
</div>
{% endif %}
<h2>Files</h2>
<ul>
  {% for file in files %}
    <li>
      <a href="{{ url_for('download_from_user', username=username, filename=file['name']) }}">{{ file['name'] }}</a>
      ({{ file['size']|default(0)|binary_filesize }}, {{ file['download_count']|default(0, true) }} downloads)
      {% if file['temporary'] %} [Temporary]{% endif %}
      {% if file['expiry'] %} [Expires: {{ file['expiry'][:16].replace('T', ' ') }}]{% endif %}
      {% if can_delete %}
        <form method="post" action="{{ url_for('delete_from_user', username=username, filename=file['name']) }}" style="display:inline;">
          <button type="submit">Delete</button>
        </form>
      {% endif %}
    </li>
  {% endfor %}
</ul>
<p><a href="/">Back to User Folders</a></p>
<script>
  function uploadFile() {
      let fileInput = document.getElementById('fileInput');
      if (!fileInput.files.length) {
          alert("Please select a file.");
          return;
      }
      let file = fileInput.files[0];
      if (file.size > MAX_UPLOAD_SIZE) {
          alert("File is too large. Maximum allowed size is " + (MAX_UPLOAD_SIZE/1024/1024).toFixed(2) + " MB.");
          return;
      }
      if (file.size + USER_USED > USER_QUOTA) {
          alert("Uploading this file would exceed your quota. You have " + ((USER_QUOTA-USER_USED)/1024/1024).toFixed(2) + " MB left.");
          return;
      }
      let formData = new FormData();
      formData.append("file", file);
      let temporary = document.getElementById('temporary').checked;
      formData.append("temporary", temporary ? '1' : '0');
      let fields = ["seconds","minutes","hours","days","weeks","months","years"];
      for (let f of fields) {
        let v = document.getElementById('expiry_' + f).value;
        formData.append('expiry_' + f, v);
      }
      let xhr = new XMLHttpRequest();
      xhr.open("POST", window.location.pathname + "/upload", true);
      document.querySelector('.progress-container').style.display = "block";
      xhr.upload.onprogress = function(event) {
          if (event.lengthComputable) {
              let percentComplete = (event.loaded / event.total) * 100;
              let progressBar = document.getElementById('progress');
              progressBar.style.width = percentComplete + "%";
              progressBar.innerText = Math.round(percentComplete) + "%";
          }
      };
      xhr.onload = function() {
          if (xhr.status == 200) {
              location.reload();
          } else {
              alert("File upload failed.");
          }
      };
      xhr.send(formData);
  }
</script>
'''

USER_UPLOAD_LIMITS = 'user_upload_limits.json'

# Ensure user upload limits file exists
if not os.path.exists(USER_UPLOAD_LIMITS):
    with open(USER_UPLOAD_LIMITS, 'w', encoding='utf-8') as f:
        json.dump({}, f)

def load_user_upload_limits():
    with open(USER_UPLOAD_LIMITS, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_user_upload_limits(limits):
    with open(USER_UPLOAD_LIMITS, 'w', encoding='utf-8') as f:
        json.dump(limits, f, indent=2)

def get_user_upload_limit(username):
    limits = load_user_upload_limits()
    val = limits.get(username, None)
    if val is None:
        return get_max_upload_size()
    return val

def set_user_upload_limit(username, limit):
    limits = load_user_upload_limits()
    limits[username] = limit
    save_user_upload_limits(limits)

@app.route('/user/<username>')
@with_expiry_cleanup
def user_folder(username):
    if 'username' not in session:
        return redirect(url_for('login'))
    users = load_users()
    if username not in users:
        flash('User not found.')
        return redirect(url_for('main'))
    folder = get_user_folder(username)
    if not os.path.exists(folder):
        os.makedirs(folder)
    stats = load_file_stats()
    files = os.listdir(folder)
    file_list = []
    for f in files:
        meta = stats.get(f, {})
        file_list.append({'name': f, **meta})
    can_upload = (session['username'] == username)
    can_delete = can_upload or is_admin()
    max_upload_size = get_user_upload_limit(username)
    user_quota = get_user_quota(username, users[username][1])
    user_used = get_user_total_upload(username)
    return render_template_string(user_folder_template, username=username, files=file_list, can_upload=can_upload, can_delete=can_delete, max_upload_size=max_upload_size, user_quota=user_quota, user_used=user_used)

@app.route('/user/<username>/upload', methods=['POST'])
@with_expiry_cleanup
def upload_to_user(username):
    if 'username' not in session or session['username'] != username:
        flash('You can only upload to your own folder.')
        return redirect(url_for('user_folder', username=username))
    user = username
    users = load_users()
    priv = users.get(user, (None, PRIV_USER))[1]
    max_upload_size = get_user_upload_limit(user)
    user_quota = get_user_quota(user, priv)
    user_total = get_user_total_upload(user)
    if 'file' not in request.files:
        flash('No file part in the request.')
        return redirect(url_for('user_folder', username=username))
    file = request.files['file']
    if file.filename == '':
        flash('No file selected.')
        return redirect(url_for('user_folder', username=username))
    if file:
        filename = secure_filename(file.filename)
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        if size > max_upload_size:
            flash(f'File exceeds max upload size ({max_upload_size // (1024*1024)} MB).')
            return redirect(url_for('user_folder', username=username))
        if user_total + size > user_quota:
            flash(f'Uploading this file would exceed your quota ({user_quota // (1024*1024)} MB).')
            return redirect(url_for('user_folder', username=username))
        temporary = request.form.get('temporary') == '1'
        # Read all expiry fields
        expiry_seconds = int(request.form.get('expiry_seconds', 0) or 0)
        expiry_minutes = int(request.form.get('expiry_minutes', 0) or 0)
        expiry_hours = int(request.form.get('expiry_hours', 0) or 0)
        expiry_days = int(request.form.get('expiry_days', 0) or 0)
        expiry_weeks = int(request.form.get('expiry_weeks', 0) or 0)
        expiry_months = int(request.form.get('expiry_months', 0) or 0)
        expiry_years = int(request.form.get('expiry_years', 0) or 0)
        expiry = None
        if temporary and (expiry_seconds or expiry_minutes or expiry_hours or expiry_days or expiry_weeks or expiry_months or expiry_years):
            now = datetime.datetime.now()
            delta = datetime.timedelta(
                seconds=expiry_seconds,
                minutes=expiry_minutes,
                hours=expiry_hours,
                days=expiry_days + expiry_weeks*7 + expiry_months*30 + expiry_years*365
            )
            expiry = (now + delta).isoformat()
        file.save(os.path.join(get_user_folder(username), filename))
        add_file_metadata(filename, user, size, expiry=expiry, temporary=temporary)
        log_file_event('upload', filename, user, request.remote_addr, {'size': size, 'temporary': temporary, 'expiry': expiry})
        if temporary and expiry:
            schedule_file_expiry(filename, user, expiry)
        return jsonify({'message': f'File "{filename}" successfully uploaded.'})

@app.route('/user/<username>/download/<filename>')
@with_expiry_cleanup
def download_from_user(username, filename):
    '''
    if 'username' not in session:
        return redirect(url_for('login'))
    '''
    increment_download_count(filename)
    log_file_event('download', filename, session['username'], request.remote_addr)
    return send_from_directory(get_user_folder(username), filename, as_attachment=True)

@app.route('/user/<username>/delete/<filename>', methods=['POST'])
@with_expiry_cleanup
def delete_from_user(username, filename):
    if 'username' not in session or (session['username'] != username and not is_admin()):
        flash('You do not have permission to delete this file.')
        return redirect(url_for('user_folder', username=username))
    folder = get_user_folder(username)
    stats = load_file_stats()
    meta = stats.get(filename)
    if not meta:
        flash('File not found.')
        return redirect(url_for('user_folder', username=username))
    try:
        os.remove(os.path.join(folder, filename))
        remove_file_metadata(filename)
        log_file_event('delete', filename, session['username'], request.remote_addr)
        flash('File deleted.')
    except Exception as e:
        flash(f'Error deleting file: {e}')
    return redirect(url_for('user_folder', username=username))

def load_file_stats():
    with open(FILE_STATS, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_file_stats(stats):
    with open(FILE_STATS, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)

def load_user_quotas():
    with open(USER_QUOTAS, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_user_quotas(quotas):
    with open(USER_QUOTAS, 'w', encoding='utf-8') as f:
        json.dump(quotas, f, indent=2)

def get_max_upload_size():
    try:
        with open(MAX_UPLOAD_SIZE_FILE, 'r', encoding='utf-8') as f:
            return int(f.read().strip())
    except Exception:
        return DEFAULT_MAX_UPLOAD_SIZE

def get_user_quota(username, priv=None):
    quotas = load_user_quotas()
    if username in quotas:
        return quotas[username]
    if priv is None:
        users = load_users()
        priv = users.get(username, (None, PRIV_USER))[1]
    if priv == PRIV_SUPERUSER:
        return DEFAULT_SUPERUSER_QUOTA
    elif priv == PRIV_ADMIN:
        return DEFAULT_ADMIN_QUOTA
    else:
        return DEFAULT_USER_QUOTA

def set_user_quota(username, quota):
    quotas = load_user_quotas()
    quotas[username] = quota
    save_user_quotas(quotas)

def get_user_total_upload(username):
    stats = load_file_stats()
    total = 0
    for meta in stats.values():
        if meta.get('uploader') == username:
            total += meta.get('size', 0)
    return total

def add_file_metadata(filename, uploader, size, expiry=None, temporary=False):
    stats = load_file_stats()
    stats[filename] = {
        'uploader': uploader,
        'upload_time': datetime.datetime.now().isoformat(),
        'size': size,
        'download_count': 0,
        'expiry': expiry,
        'temporary': temporary
    }
    save_file_stats(stats)

def increment_download_count(filename):
    stats = load_file_stats()
    if filename in stats:
        stats[filename]['download_count'] = stats[filename].get('download_count', 0) + 1
        save_file_stats(stats)

def remove_file_metadata(filename):
    stats = load_file_stats()
    if filename in stats:
        del stats[filename]
        save_file_stats(stats)

expiry_timers = {}

def schedule_file_expiry(filename, uploader, expiry_iso):
    try:
        expiry_time = datetime.datetime.fromisoformat(expiry_iso)
        now = datetime.datetime.now()
        seconds = (expiry_time - now).total_seconds()
        if seconds <= 0:
            # Already expired, delete immediately
            folder = get_user_folder(uploader)
            try:
                os.remove(os.path.join(folder, filename))
            except Exception:
                pass
            remove_file_metadata(filename)
            log_file_event('expired_delete', filename, 'system', 'localhost')
            return
        def delete_file_at_expiry():
            folder = get_user_folder(uploader)
            try:
                os.remove(os.path.join(folder, filename))
            except Exception:
                pass
            remove_file_metadata(filename)
            log_file_event('expired_delete', filename, 'system', 'localhost')
        timer = threading.Timer(seconds, delete_file_at_expiry)
        timer.daemon = True
        timer.start()
        expiry_timers[(filename, uploader)] = timer
    except Exception:
        pass

def reschedule_all_expiry_timers():
    stats = load_file_stats()
    for fname, meta in stats.items():
        if meta.get('temporary') and meta.get('expiry') and meta.get('uploader'):
            schedule_file_expiry(fname, meta['uploader'], meta['expiry'])

admin_template = '''
<!doctype html>
<title>Admin Controls</title>
<h2>Admin Controls</h2>
<form method="post" action="{{ url_for('admin') }}">
  <h3>Set Global Max Upload Size (MB)</h3>
  <input type="number" name="max_upload_size" min="1" value="{{ max_upload_size // (1024*1024) }}">
  <button type="submit" name="action" value="set_max_upload_size">Update</button>
</form>
<h3>User Quotas & Upload Limits (MB)</h3>
<form method="post" action="{{ url_for('admin') }}">
  <table border="1" style="margin:auto;">
    <tr><th>Username</th><th>Current Quota</th><th>Set New Quota</th><th>Current Upload Limit</th><th>Set New Upload Limit</th></tr>
    {% for user in user_quotas.keys() %}
      <tr>
        <td>{{ user }}</td>
        <td>{{ user_quotas[user] // (1024*1024) }}</td>
        <td><input type="number" name="quota_{{ user }}" min="1"></td>
        <td>{% if user_upload_limits[user] is not none %}{{ user_upload_limits[user] // (1024*1024) }}{% else %}{{ max_upload_size // (1024*1024) }} (global){% endif %}</td>
        <td><input type="number" name="upload_limit_{{ user }}" min="1" placeholder="(blank=global)"></td>
      </tr>
    {% endfor %}
  </table>
  <button type="submit" name="action" value="set_quotas">Update Quotas & Upload Limits</button>
</form>

<h3>User Management</h3>
<table border="1" style="margin:auto;">
  <tr><th>Username</th><th>Privilege</th><th>Change Password</th><th>Promote/Demote</th><th>Delete User</th></tr>
  {% for user in users.keys() %}
    <tr>
      <td>{{ user }}</td>
      <td>{{ users[user][1] }}</td>
      <td>
        <form method="post" action="{{ url_for('admin') }}" style="display:inline;">
          <input type="hidden" name="action" value="change_password">
          <input type="hidden" name="target_user" value="{{ user }}">
          <input type="password" name="new_password" placeholder="New password">
          <button type="submit">Set</button>
        </form>
      </td>
      <td>
        <form method="post" action="{{ url_for('admin') }}" style="display:inline;">
          <input type="hidden" name="target_user" value="{{ user }}">
          {% if users[user][1] == '0' %}
            <input type="hidden" name="action" value="promote">
            <button type="submit">Promote to Admin</button>
          {% elif users[user][1] == '1' %}
            <input type="hidden" name="action" value="demote">
            <button type="submit">Demote to User</button>
          {% else %}
            Superuser
          {% endif %}
        </form>
      </td>
      <td>
        <form method="post" action="{{ url_for('admin') }}" style="display:inline;" onsubmit="return confirm('Delete user {{ user }} and all their files?');">
          <input type="hidden" name="action" value="delete_user">
          <input type="hidden" name="target_user" value="{{ user }}">
          <button type="submit">Delete</button>
        </form>
      </td>
    </tr>
  {% endfor %}
</table>
<p><a href="/">Back to File List</a></p>
'''

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not is_admin():
        flash('Admin access required.')
        return redirect(url_for('main'))
    max_upload_size = get_max_upload_size()
    user_quotas = load_user_quotas()
    user_upload_limits = load_user_upload_limits()
    users = load_users()
    # Add all users to quotas dict if missing
    for u in users:
        if u not in user_quotas:
            user_quotas[u] = get_user_quota(u, users[u][1])
        if u not in user_upload_limits:
            user_upload_limits[u] = None
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'set_max_upload_size':
            try:
                new_size = int(request.form.get('max_upload_size')) * 1024 * 1024
                with open(MAX_UPLOAD_SIZE_FILE, 'w', encoding='utf-8') as f:
                    f.write(str(new_size))
                flash('Max upload size updated.')
            except Exception as e:
                flash(f'Error updating max upload size: {e}')
        elif action == 'set_quotas':
            for u in users:
                qval = request.form.get(f'quota_{u}')
                if qval:
                    try:
                        user_quotas[u] = int(qval) * 1024 * 1024
                    except Exception:
                        pass
                ulval = request.form.get(f'upload_limit_{u}')
                if ulval:
                    try:
                        user_upload_limits[u] = int(ulval) * 1024 * 1024
                    except Exception:
                        pass
                elif ulval == '':
                    user_upload_limits[u] = None
            save_user_quotas(user_quotas)
            save_user_upload_limits(user_upload_limits)
            flash('User quotas and upload limits updated.')
        elif action == 'change_password':
            target_user = request.form.get('target_user')
            new_password = request.form.get('new_password')
            if target_user and new_password:
                pw_hash = generate_password_hash(new_password)
                # Update users.txt
                lines = []
                with open(USERS_FILE, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.startswith(target_user + ':'):
                            parts = line.strip().split(':')
                            priv = parts[-1]
                            lines.append(f"{target_user}:{pw_hash}:{priv}\n")
                        else:
                            lines.append(line)
                with open(USERS_FILE, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
                flash(f'Password for {target_user} updated.')
            else:
                flash('Missing target user or new password.')
        elif action == 'delete_user':
            target_user = request.form.get('target_user')
            if target_user:
                # Remove from users.txt
                lines = []
                with open(USERS_FILE, 'r', encoding='utf-8') as f:
                    for line in f:
                        if not line.startswith(target_user + ':'):
                            lines.append(line)
                with open(USERS_FILE, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
                # Remove from quotas and upload limits
                user_quotas.pop(target_user, None)
                user_upload_limits.pop(target_user, None)
                save_user_quotas(user_quotas)
                save_user_upload_limits(user_upload_limits)
                # Remove user folder and files
                folder = get_user_folder(target_user)
                if os.path.exists(folder):
                    for fname in os.listdir(folder):
                        try:
                            os.remove(os.path.join(folder, fname))
                        except Exception:
                            pass
                    try:
                        os.rmdir(folder)
                    except Exception:
                        pass
                # Remove file metadata for their files
                stats = load_file_stats()
                to_remove = [fname for fname, meta in stats.items() if meta.get('uploader') == target_user]
                for fname in to_remove:
                    remove_file_metadata(fname)
                flash(f'User {target_user} and their files deleted.')
            else:
                flash('Missing target user.')
        elif action == 'promote':
            target_user = request.form.get('target_user')
            if target_user:
                # Promote to admin
                lines = []
                with open(USERS_FILE, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.startswith(target_user + ':'):
                            parts = line.strip().split(':')
                            pw_hash = ':'.join(parts[1:-1])
                            lines.append(f"{target_user}:{pw_hash}:1\n")
                        else:
                            lines.append(line)
                with open(USERS_FILE, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
                flash(f'User {target_user} promoted to admin.')
        elif action == 'demote':
            target_user = request.form.get('target_user')
            if target_user:
                # Demote to user
                lines = []
                with open(USERS_FILE, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.startswith(target_user + ':'):
                            parts = line.strip().split(':')
                            pw_hash = ':'.join(parts[1:-1])
                            lines.append(f"{target_user}:{pw_hash}:0\n")
                        else:
                            lines.append(line)
                with open(USERS_FILE, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
                flash(f'User {target_user} demoted to user.')
    return render_template_string(admin_template, max_upload_size=max_upload_size, user_quotas=user_quotas, user_upload_limits=user_upload_limits, users=users)

def start_expiry_cleanup_thread():
    def run():
        while True:
            try:
                cleanup_expired_files()
            except Exception:
                pass
            time.sleep(60)  # Run every 60 seconds
    t = threading.Thread(target=run, daemon=True)
    t.start()

if __name__ == '__main__':
    reschedule_all_expiry_timers()
    start_expiry_cleanup_thread()
    app.run(host='0.0.0.0', port=5007, debug=True)
