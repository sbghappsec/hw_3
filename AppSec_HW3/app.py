import sys
from flask import Flask, render_template, flash, redirect, url_for, session, send_from_directory, request
from forms import RegistrationForm, LoginForm, UploadForm
from passlib.hash import sha256_crypt
from flask_sqlalchemy import SQLAlchemy
from werkzeug import secure_filename
from spell_checker import spellchecker
import os
import base64
import json
from werkzeug.datastructures import FileStorage
from io import BytesIO
from ast import literal_eval
import shutil  # used later to DELETE a folder from the storage
import logging
from logging.handlers import RotatingFileHandler
import datetime
from functools import wraps

app = Flask(__name__)
# key to encrypt cookie data
app.config['SECRET_KEY'] = '467884264a98e0ab2832dc708e4b147e690ef88deac7b3f0a2c858153c6c32a3'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/appsec'
# directory where user uploads will be stored
# change username
app.config['UPLOAD_FOLDER'] = '/home/user/AppSec_WebApp/uploads/'
app.config['MAX_CONTENT_LENGTH'] = 1 * \
    1024 * 1024  # allow .txt file size of 1mb
db = SQLAlchemy(app)


class User(db.Model):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    __tablename__ = 'User'
    username = db.Column('username', db.Unicode, primary_key=True)
    password = db.Column('password', db.Unicode)

# modifed from flask documentation
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# log attempts to load unkown url, possible file inclusion attack 
@app.errorhandler(404)
def unknown_page(e):
    if 'username' in session:
        app.logger.error(f"{session['username']} from {request.remote_addr} tried to access {request.url}: UNAUTHORIZED ACCESS")
    else:
        app.logger.error(f"{request.remote_addr} tried to access {request.url}")
    flash('That page could not be found!')
    return render_template('home.html'), 404


@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = sha256_crypt.hash(form.password.data)
        if not User.query.filter_by(username=username).first():
            user = User(username, password)
            db.session.add(user)
            db.session.commit()
            flash(f'Registration Successful')
            app.logger.error(
                f"username: '{username}': created at {datetime.datetime.now()} from IP: {request.remote_addr} REGISTRATION SUCCESS")
            return redirect(url_for('home'))
        flash("That username is taken.")
    return render_template('register.html', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        entry = User.query.filter_by(username=username).first()
        if entry and sha256_crypt.verify(password, entry.password):
            session['username'] = username
            flash(f'Login Successful')
            app.logger.error(
                f"username: '{['username']}': logged in at {datetime.datetime.now()} from IP: {request.remote_addr}: LOGIN SUCCESS")
            return redirect(url_for('home'))
        app.logger.error(f"{username}: failed to log in: LOGIN FAILURE")
        flash('Password incorrect.')
    return render_template('login.html', form=form)


@app.route("/logout")
@login_required
def logout():
    app.logger.error(f"username: '{session['username']}': logged out at {datetime.datetime.now()} from IP: {request.remote_addr}: LOGOUT")
    session.pop('username', None)
    return redirect(url_for('home'))


@app.route("/uploads/")
@login_required
def uploads():
    app.logger.error(
        f"{session['username']} accessed uploads at {datetime.datetime.now()} from IP: {request.remote_addr}: ACCESSED UPLOADS")

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
    if not os.path.exists(file_path):
        flash("You haven't uploaded any files yet.")
        return render_template('uploads.html')
    uploaded = []
    errors = {}
    for items in os.listdir(file_path):
        if os.path.isdir(file_path + '/' + items):  # avoid adding errors subdirectory
            continue
        filename = session['username'] + '/' + items
        sent = send_from_directory(app.config['UPLOAD_FOLDER'], filename)
        sent.direct_passthrough = False
        decoded = base64.b64decode(sent.data)
        uploaded.append((items, decoded.decode('ascii')))
        delet = file_path + '/' + 'errors/' + items
        if os.path.exists(file_path + '/' + 'errors/' + items):
            errors_sent = send_from_directory(
                app.config['UPLOAD_FOLDER'], session['username'] + '/' + 'errors/' + items)
            errors_sent.direct_passthrough = False
            errors[items] = literal_eval(errors_sent.data.decode('ascii'))
    return render_template('uploads.html', uploads=uploaded, errors=errors)


@app.route("/spellcheck", methods=['GET', 'POST'])
@login_required
def spellcheck():
    form = UploadForm()
    if request.method == 'POST':
        try:
            app.logger.error(
                f"{session['username']} attempted to upload {form.upload.data.filename}: UPLOAD ATTEMPT")
        except AttributeError:
            app.logger.error(
                f"{session['username']} accessed spellchecker at {datetime.datetime.now()} from IP: {request.remote_addr}: ACCESSED SPELLCHECKER")
        if form.validate_on_submit():
            app.logger.error(
                f"{session['username']} uploaded {form.upload.data.filename} successfully: UPLOAD SUCCESS")
            f = form.upload.data
            filename = secure_filename(f.filename)
            errors = spellchecker(filename)
            encoded = base64.b64encode(f.read())
            encoded = FileStorage(BytesIO(encoded), filename)
            file_path = os.path.join(
                app.config['UPLOAD_FOLDER'], session['username'])
            errors_file_path = os.path.join(
                app.config['UPLOAD_FOLDER'], session['username'], 'errors')
            if os.path.exists(file_path):
                files = os.walk(file_path).__next__()[2]
                if len(files) >= 5:
                    # this will DELETE the user's folder from storage
                    shutil.rmtree(file_path)
                    flash('Storage limit exceeded. Your storage has reset.')
            if not os.path.exists(file_path):
                os.makedirs(file_path)
            if not os.path.exists(errors_file_path):
                os.makedirs(errors_file_path)
            encoded.save(os.path.join(file_path, filename))  # save file
            with open(errors_file_path + '/' + filename, 'w') as errors_file:
                errors_file.write(json.dumps(errors))
            return redirect(url_for('uploads'))
        app.logger.error(
                f"{session['username']} attempted to upload {form.upload.data.filename}: UPLOAD FAILURE")
        upload_logger.error(f"{session['username']} attempted to upload {form.upload.data.filename} at {datetime.datetime.now()} from IP: {request.remote_addr} with content: {form.upload.data.read()}")

    return render_template('spellcheck.html', form=form)


if __name__ == '__main__':
    logHandler = RotatingFileHandler(
        'errors.log', maxBytes=1000, backupCount=5) # number of backups when first is filled
    logHandler.setLevel(logging.ERROR)
    app.logger.addHandler(logHandler)
    # to log file uploads
    errorHandler = RotatingFileHandler(
        'upload_errors.log', maxBytes=5000, backupCount=5) # number of backups when first is filled
    errorHandler.setLevel(logging.ERROR)
    upload_logger = logging.getLogger('upload_errors')
    upload_logger.setLevel(logging.ERROR)
    upload_logger.addHandler(errorHandler)
    # app.run(debug=True)
    app.run()
