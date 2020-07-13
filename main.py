from flask import (Flask,
                   session,
                   redirect,
                   url_for,
                   request,
                   render_template,
                   flash,
                   abort)  # g, escape
from werkzeug.security import (generate_password_hash,
                               check_password_hash)
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms.fields import (StringField,
                            PasswordField,
                            TextAreaField,
                            BooleanField,
                            SubmitField,
                            IntegerField,
                            SelectField)  # RadioField
from wtforms.fields.html5 import DateField
from wtforms.widgets import Select
from wtforms.widgets.html5 import (DateInput,
                                   NumberInput)
from wtforms.validators import (DataRequired,
                                Email,
                                EqualTo,
                                Optional)  # Length, NumberRange
from flask_script import Manager
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from config import Config
from datetime import datetime
from cryptography.fernet import Fernet

app = Flask(__name__)
app.config.from_object(Config)
manager = Manager(app)
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)


# Database Model
# ----------------------------------------------------------------------------------------------------------------------
class AppUser(db.Model):
    __tablename__ = 'tapp_user'
    user_id = db.Column(db.Integer(), primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    user_email = db.Column(db.String(80), nullable=False, unique=True)
    user_pass = db.Column(db.String(100), nullable=False)
    activated_ts = db.Column(db.DateTime(), nullable=True)
    audit_crt_ts = db.Column(db.DateTime(), nullable=False)
    audit_upd_ts = db.Column(db.DateTime(), nullable=True)
    secrets = db.relationship('Secret', backref='tapp_user', lazy='dynamic')

    def __init__(self, first_name, last_name, user_email, user_pass, audit_crt_ts):
        self.first_name = first_name
        self.last_name = last_name
        self.user_email = user_email
        self.user_pass = user_pass
        self.audit_crt_ts = audit_crt_ts

    def __repr__(self):
        return '<user: {} {}>'.format(self.first_name, self.last_name)

    def user_name(self):
        return '{} {}'.format(self.first_name, self.last_name)


class Secret(db.Model):
    __tablename__ = 'tsecret'
    secret_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('tapp_user.user_id'))
    secret_name = db.Column(db.String(50), nullable=False)
    secret_text = db.Column(db.Text(), nullable=False, default='')

    def __init__(self, user_id, secret_name, secret_text):
        self.user_id = user_id
        self.secret_name = secret_name
        self.secret_text = secret_text

    def __repr__(self):
        return '<secret: {}:{}>'.format(self.secret_id, self.secret_name)


# Classes pour définir les formulaires WTF
# ----------------------------------------------------------------------------------------------------------------------

# Formulaire pour confirmer la suppression d'une entitée
class DelEntityForm(FlaskForm):
    submit = SubmitField('Supprimer')


# Formulaire web pour l'écran de login
class LoginForm(FlaskForm):
    email = StringField('Courriel', validators=[DataRequired(), Email(message='Le courriel est invalide.')])
    password = PasswordField('Mot de Passe', [DataRequired(message='Le mot de passe est obligatoire.')])
    request_password_change = BooleanField('Changer le mot de passe?')
    password_1 = PasswordField('Nouveau Mot de passe',
                               [EqualTo('password_2', message='Les mots de passe doivent être identiques.')])
    password_2 = PasswordField('Confirmation')
    submit = SubmitField('Se connecter')


# Formulaire web pour l'écran de register
class RegisterForm(FlaskForm):
    first_name = StringField('Prénom', validators=[DataRequired(message='Le prénom est requis.')])
    last_name = StringField('Nom de famille', validators=[DataRequired(message='Le nom de famille est requis.')])
    email = StringField('Courriel', validators=[DataRequired(), Email(message='Le courriel est invalide.')])
    password_1 = PasswordField('Mot de passe',
                               [DataRequired(message='Le mot de passe est obligatoire.'),
                                EqualTo('password_2', message='Les mots de passe doivent être identiques.')])
    password_2 = PasswordField('Confirmation')
    submit = SubmitField('S\'enrégistrer')


# Formulaires pour ajouter une liste de tâches
class AddSecretForm(FlaskForm):
    secret_name = StringField('Nom du secret', validators=[DataRequired(message='Le nom est requis.')])
    secret_text = TextAreaField('Texte secret')
    submit = SubmitField('Ajouter')


# Formulaire de la mise à jour d'une liste de tâches
class UpdSecretForm(FlaskForm):
    secret_name = StringField('Nom du secret', validators=[DataRequired(message='Le nom est requis.')])
    secret_text = TextAreaField('Texte secret')
    submit = SubmitField('Modifier')


# The following functions are views
# ----------------------------------------------------------------------------------------------------------------------

# Custom error pages
@app.errorhandler(404)
def page_not_found(e):
    app.logger.error('Page non trouvée. ' + str(e))
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error('Erreur interne. ' + str(e))
    return render_template('500.html'), 500


# Index
@app.route('/')
def index():
    if not logged_in():
        return redirect(url_for('login'))
    app.logger.debug('Entering index()')
    first_name = session.get('first_name', None)
    return render_template('secret.html', user=first_name)


# Views for Register, logging in, logging out and listing users
@app.route('/login', methods=['GET', 'POST'])
def login():
    # The method is GET when the form is displayed and POST to process the form
    app.logger.debug('Entering login()')
    form = LoginForm()
    if form.validate_on_submit():
        user_email = request.form['email']
        password = request.form['password']
        if db_validate_user(user_email, password):
            session['active_time'] = datetime.now()
            request_pwd_change = request.form.get('request_password_change', None)
            if request_pwd_change:
                app.logger.debug("Changer le mot de passe")
                new_password = request.form['password_1']
                db_change_password(user_email, new_password)
            return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    app.logger.debug('Entering logout()')
    session.pop('user_id', None)
    session.pop('first_name', None)
    session.pop('last_name', None)
    session.pop('user_email', None)
    session.pop('active_time', None)
    flash('Vous êtes maintenant déconnecté.')
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    app.logger.debug('Entering register')
    form = RegisterForm()
    if form.validate_on_submit():
        app.logger.debug('Inserting a new registration')
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        user_email = request.form['email']
        user_pass = generate_password_hash(request.form['password_1'])
        if db_user_exists(user_email):
            flash('Cet usager existe déjà. Veuillez vous connecter.')
            return redirect(url_for('login'))
        else:
            if db_add_user(first_name, last_name, user_email, user_pass):
                flash('Vous pourrez vous connecter quand votre usager sera activé.')
                return redirect(url_for('login'))
            else:
                flash('Une erreur de base de données est survenue.')
                abort(500)
    return render_template('register.html', form=form)


@app.route('/list_users')
def list_users():
    if not logged_in():
        return redirect(url_for('login'))
    try:
        user_id = session.get('user_id')
        admin_user = AppUser.query.filter_by(user_id=user_id, user_email=app.config.get('ADMIN_EMAILID')).first()
        app_users = AppUser.query.order_by(AppUser.first_name).all()
        return render_template('list_users.html', app_users=app_users, admin_user=admin_user)
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return redirect(url_for('index'))


@app.route('/act_user/<int:user_id>', methods=['GET', 'POST'])
def act_user(user_id):
    if not logged_in():
        return redirect(url_for('login'))
    if db_upd_user_status(user_id, 'A'):
        flash("L'utilisateur est activé.")
    else:
        flash("Quelque chose n'a pas fonctionné.")
    return redirect(url_for('list_users'))


@app.route('/inact_user/<int:user_id>', methods=['GET', 'POST'])
def inact_user(user_id):
    if not logged_in():
        return redirect(url_for('login'))
    if db_upd_user_status(user_id, 'D'):
        flash("L'utilisateur est désactivé.")
    else:
        flash("Quelque chose n'a pas fonctionné.")
    return redirect(url_for('list_users'))


@app.route('/del_user/<int:user_id>', methods=['GET', 'POST'])
def del_user(user_id):
    if not logged_in():
        return redirect(url_for('login'))
    form = DelEntityForm()
    if form.validate_on_submit():
        app.logger.debug('Deleting a user')
        if db_del_user(user_id):
            flash("L'utilisateur a été effacé.")
        else:
            flash("Quelque chose n'a pas fonctionné.")
        return redirect(url_for('list_users'))
    else:
        user = db_user_by_id(user_id)
        if user:
            return render_template('del_user.html', form=form, user=user)
        else:
            flash("L'information n'a pas pu être retrouvée.")
            return redirect(url_for('list_users'))


# Views for Lists of Tasks
# Ordre des vues: list, show, add, upd, del
@app.route('/list_secrets')
def list_secrets():
    if not logged_in():
        return redirect(url_for('login'))
    try:
        user_id = session.get('user_id')
        secrets = Secret.query.filter_by(user_id=user_id).order_by(Secret.secret_name).all()
        return render_template('list_secrets.html', secrets=secrets)
    except Exception as e:
        flash("Quelque chose n'a pas fonctionné.")
        app.logger.error('Error: ' + str(e))
        abort(500)


@app.route('/show_secret/<int:secret_id>')
def show_secret(secret_id):
    if not logged_in():
        return redirect(url_for('login'))
    try:
        user_id = session.get('user_id')
        secret = db_secret_by_id(user_id, secret_id)
        if secret:
            return render_template("show_secret.html", secret=secret)
        else:
            flash("L'information n'a pas pu être retrouvée.")
            return redirect(url_for('list_secrets'))
    except Exception as e:
        flash("Quelque chose n'a pas fonctionné.")
        app.logger.error('Error: ' + str(e))
        abort(500)


@app.route('/add_secret', methods=['GET', 'POST'])
def add_secret():
    if not logged_in():
        return redirect(url_for('login'))
    app.logger.debug('Entering add_secret')
    form = AddSecretForm()
    if form.validate_on_submit():
        app.logger.debug('Inserting a new secret')
        secret_name = request.form['secret_name']
        secret_text = request.form['secret_text']
        user_id = session.get('user_id')
        if db_secret_exists(user_id, secret_name):
            flash('Ce nom de secret existe déjà. Veuillez en choisir un autre.')
            return render_template('add_secret.html', form=form)
        else:
            if db_add_secret(user_id, secret_name, secret_text):
                flash('Le nouveau est ajouté.')
                return redirect(url_for('list_secrets'))
            else:
                flash('Une erreur de base de données est survenue.')
                abort(500)
    return render_template('add_secret.html', form=form)


@app.route('/upd_secret/<int:secret_id>', methods=['GET', 'POST'])
def upd_secret(secret_id):
    if not logged_in():
        return redirect(url_for('login'))
    user_id = session.get('user_id')
    secret = db_secret_by_id(user_id, secret_id)
    if secret is None:
        flash("L'information n'a pas pu être retrouvée.")
        return redirect(url_for('list_secrets'))
    form = UpdSecretForm()
    if form.validate_on_submit():
        app.logger.debug('Updating a secret')
        save_secret_name = secret.secret_name
        secret_name = form.secret_name.data
        secret_text = form.secret_text.data
        if (secret_name != save_secret_name) and db_secret_exists(user_id, secret_name):
            flash('Ce nom de secret existe déjà. Veuillez en choisir un autre.')
            return render_template("upd_secret.html", form=form, secret=secret)
        if db_upd_secret(secret_id, secret_name, secret_text):
            flash("Le secret a été modifié.")
        else:
            flash("Quelque chose n'a pas fonctionné.")
        return redirect(url_for('list_secrets'))
    else:
        form.secret_name.data = secret.secret_name
        form.secret_text.data = secret.secret_text
        return render_template("upd_secret.html", form=form, secret=secret)


@app.route('/del_secret/<int:secret_id>', methods=['GET', 'POST'])
def del_secret(secret_id):
    if not logged_in():
        return redirect(url_for('login'))
    user_id = session.get('user_id')
    form = DelEntityForm()
    if form.validate_on_submit():
        app.logger.debug('Deleting a secret')
        if db_del_secret(secret_id):
            flash("Le secret a été effacé.")
        else:
            flash("Quelque chose n'a pas fonctionné.")
        return redirect(url_for('list_secrets'))
    else:
        secret = db_secret_by_id(user_id, secret_id)
        if secret:
            return render_template('del_secret.html', form=form, secret=secret)
        else:
            flash("L'information n'a pas pu être retrouvée.")
            return redirect(url_for('list_secrets'))


# Application functions
# ----------------------------------------------------------------------------------------------------------------------
def logged_in():
    user_email = session.get('user_email', None)
    if user_email:
        active_time = session['active_time']
        delta = datetime.now() - active_time
        if (delta.days > 0) or (delta.seconds > 1800):
            flash('Votre session est expirée.')
            return False
        session['active_time'] = datetime.now()
        return True
    else:
        return False


# Database functions
# ----------------------------------------------------------------------------------------------------------------------

# Database functions for AppUser
def db_add_user(first_name, last_name, user_email, user_pass):
    audit_crt_ts = datetime.now()
    try:
        user = AppUser(first_name, last_name, user_email, user_pass, audit_crt_ts)
        if user_email == app.config.get('ADMIN_EMAILID'):
            user.activated_ts = datetime.now()
        db.session.add(user)
        db.session.commit()
        return True
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return False


def db_upd_user_status(user_id, status):
    try:
        user = AppUser.query.get(user_id)
        if status == 'A':
            user.activated_ts = datetime.now()
        else:
            user.activated_ts = None
        db.session.commit()
        return True
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return False


def db_user_exists(user_email):
    app.logger.debug('Entering user_exists with: ' + user_email)
    try:
        user = AppUser.query.filter_by(user_email=user_email).first()
        if user is None:
            return False
        else:
            return True
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return False


def db_user_by_id(user_id):
    try:
        u = AppUser.query.get(user_id)
        return u
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return None


def db_change_password(user_email, new_password):
    try:
        user = AppUser.query.filter_by(user_email=user_email).first()
        if user is None:
            flash("Mot de passe inchangé. L'usager n'a pas été retrouvé.")
            return False
        else:
            user.user_pass = generate_password_hash(new_password)
            user.audit_upd_ts = datetime.now()
            db.session.commit()
            flash("Mot de passe changé.")
            return True
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        flash("Mot de passe inchangé. Une erreur interne s'est produite.")
        return False


# Validate if a user is defined in tapp_user with the proper password.
def db_validate_user(user_email, password):
    try:
        user = AppUser.query.filter_by(user_email=user_email).first()
        if user is None:
            flash("L'usager n'existe pas.")
            return False

        if not user.activated_ts:
            flash("L'usager n'est pas activé.")
            return False

        if check_password_hash(user.user_pass, password):
            session['user_id'] = user.user_id
            session['user_email'] = user.user_email
            session['first_name'] = user.first_name
            session['last_name'] = user.last_name
            return True
        else:
            flash("Mauvais mot de passe!")
            return False
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        flash("Connection impossible. Une erreur interne s'est produite.")
        return False


def db_del_user(user_id):
    try:
        user = AppUser.query.get(user_id)
        for secret in user.secrets:
            db.session.delete(secret)
        db.session.delete(user)
        db.session.commit()
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return False
    return True


# DB functions for TaskList: exists, by_id, add, upd, del, others
def db_secret_exists(user_id, secret_name):
    app.logger.debug('Entering secret_exists with: ' + secret_name)
    try:
        secret = Secret.query.filter_by(user_id=user_id, secret_name=secret_name).first()
        if secret is None:
            return False
        else:
            return True
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return False


def db_secret_by_id(user_id, secret_id):
    try:
        secret = Secret.query.filter_by(secret_id=secret_id, user_id=user_id).first()
        if secret:
            secret.secret_text = decrypt_message(secret.secret_text)
        else:
            return None
        return secret
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return None


def db_add_secret(user_id, secret_name, secret_text):
    secret_text = encrypt_message(secret_text)
    secret = Secret(user_id, secret_name, secret_text)
    try:
        db.session.add(secret)
        db.session.commit()
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return False
    return True


def db_upd_secret(secret_id, secret_name, secret_text):
    try:
        secret = Secret.query.get(secret_id)
        secret.secret_name = secret_name
        secret.secret_text = encrypt_message(secret_text)
        db.session.commit()
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return False
    return True


def db_del_secret(secret_id):
    try:
        secret = Secret.query.get(secret_id)
        db.session.delete(secret)
        db.session.commit()
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return False
    return True


def load_key():
    """
    Load the previously generated key
    """
    key_file = app.config.get('ENCRYPT_KEY_FILE')
    return open(key_file, "rb").read()


def encrypt_message(message):
    """
    Encrypts a message
    """
    key = load_key()
    encoded_message = message.encode()
    f = Fernet(key)
    return f.encrypt(encoded_message)


def decrypt_message(encrypted_message):
    """
    Decrypts an encrypted message
    """
    key = load_key()
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode()


# Start the server for the application
if __name__ == '__main__':
    manager.run()
