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
    user_role = db.Column(db.String(10), nullable=False, default='Régulier')  # Admin or Régulier
    secrets = db.relationship('Secret', backref='tapp_user', lazy='dynamic')
    servers = db.relationship('Server', backref='tapp_user', lazy='dynamic')
    #srv_usrs = db.relationship('ServerUser', backref='tapp_user', lazy='dynamic')

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


class Server(db.Model):
    __tablename__ = 'tserver'
    srvr_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('tapp_user.user_id'))
    srvr_name = db.Column(db.String(16), nullable=False)
    srvr_fqn = db.Column(db.String(64), nullable=True)
    srvr_desc = db.Column(db.Text(), nullable=True)
    srvr_accounts = db.relationship('ServerAccount', backref='tapp_user', lazy='dynamic')

    def __init__(self, user_id, srvr_name, srvr_fqn, srvr_desc):
        self.user_id = user_id
        self.srvr_name = srvr_name
        self.srvr_fqn = srvr_fqn
        self.srvr_desc = srvr_desc

    def __repr__(self):
        return '<server: {}:{}>'.format(self.srvr_id, self.srvr_name)


class ServerAccount(db.Model):
    __tablename__ = 'tserver_account'
    srvr_acct_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    srvr_id = db.Column(db.Integer, db.ForeignKey('tserver.srvr_id'))
    account_name = db.Column(db.String(32), nullable=False)
    account_pass = db.Column(db.Text(), nullable=False, default='')
    account_desc = db.Column(db.Text(), nullable=True)

    def __init__(self, srvr_id, account_name, account_pass, account_desc):
        self.srvr_id = srvr_id
        self.account_name = account_name
        self.account_pass = account_pass
        self.account_desc = account_desc

    def __repr__(self):
        return '<server-user: {}:{}>'.format(self.srvusr_id, self.account_name)


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


# Formulaires pour ajouter un secret
class AddSecretForm(FlaskForm):
    secret_name = StringField('Nom de la note', validators=[DataRequired(message='Le nom est requis.')])
    secret_text = TextAreaField('Texte')
    submit = SubmitField('Ajouter')


# Formulaire de la mise à jour d'un secret
class UpdSecretForm(FlaskForm):
    secret_name = StringField('Nom de la note', validators=[DataRequired(message='Le nom est requis.')])
    secret_text = TextAreaField('Texte')
    submit = SubmitField('Modifier')


# Formulaires pour ajouter un serveur
class AddServerForm(FlaskForm):
    srvr_name = StringField('Nom du serveur', validators=[DataRequired(message='Le nom est requis.')])
    srvr_fqn = StringField('Fully Qualified Name')
    srvr_desc = TextAreaField('Description')
    submit = SubmitField('Ajouter')


# Formulaire de la mise à jour d'un serveur
class UpdServerForm(FlaskForm):
    srvr_name = StringField('Nom du serveur', validators=[DataRequired(message='Le nom est requis.')])
    srvr_fqn = StringField('Fully Qualified Name')
    srvr_desc = TextAreaField('Description')
    submit = SubmitField('Modifier')


# Formulaires pour ajouter un compte sur serveur
class AddSrvrAcctForm(FlaskForm):
    account_name = StringField('Nom du compte', validators=[DataRequired(message='Le nom est requis.')])
    account_pass = StringField('Mot de passe', [DataRequired(message='Le mot de passe est obligatoire.')])
    account_desc = TextAreaField('Description')
    submit = SubmitField('Ajouter')


# Formulaire de la mise à jour d'un compte sur serveur
class UpdSrvrAcctForm(FlaskForm):
    account_name = StringField('Nom du compte', validators=[DataRequired(message='Le nom est requis.')])
    account_pass = StringField('Mot de passe', [DataRequired(message='Le mot de passe est obligatoire.')])
    account_desc = TextAreaField('Description')
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
            flash('Cet utilisateur existe déjà. Veuillez vous connecter.')
            return redirect(url_for('login'))
        else:
            if db_add_user(first_name, last_name, user_email, user_pass):
                flash('Vous pourrez vous connecter quand votre utilisateur sera activé.')
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
        admin_user = db_user_is_admin(user_id)
        app_users = AppUser.query.order_by(AppUser.first_name).all()
        return render_template('list_users.html', app_users=app_users, admin_user=admin_user)
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return redirect(url_for('index'))


@app.route('/act_user/<int:user_id>', methods=['GET', 'POST'])
def act_user(user_id):
    if not logged_in():
        return redirect(url_for('login'))
    cur_user_id = session.get('user_id')
    if db_user_is_admin(cur_user_id):
        if db_upd_user_status(user_id, 'A'):
            flash("L'utilisateur est activé.")
        else:
            flash("Quelque chose n'a pas fonctionné.")
    else:
        flash("Vous n'êtes pas autorisé à changer le status d'un utilisateur.")
    return redirect(url_for('list_users'))


@app.route('/inact_user/<int:user_id>', methods=['GET', 'POST'])
def inact_user(user_id):
    if not logged_in():
        return redirect(url_for('login'))
    cur_user_id = session.get('user_id')
    if db_user_is_admin(cur_user_id):
        if db_upd_user_status(user_id, 'D'):
            flash("L'utilisateur est désactivé.")
        else:
            flash("Quelque chose n'a pas fonctionné.")
    else:
        flash("Vous n'êtes pas autorisé à changer le status d'un utilisateur.")
    return redirect(url_for('list_users'))


@app.route('/set_user_admin/<int:user_id>', methods=['GET', 'POST'])
def set_user_admin(user_id):
    if not logged_in():
        return redirect(url_for('login'))
    cur_user_id = session.get('user_id')
    if db_user_is_admin(cur_user_id):
        if db_upd_user_role(user_id, 'A'):
            flash("L'utilisateur est maintenant administrateur.")
        else:
            flash("Quelque chose n'a pas fonctionné.")
    else:
        flash("Vous n'êtes pas autorisé à changer le rôle d'un utilisateur.")
    return redirect(url_for('list_users'))


@app.route('/set_user_regular/<int:user_id>', methods=['GET', 'POST'])
def set_user_regular(user_id):
    if not logged_in():
        return redirect(url_for('login'))
    cur_user_id = session.get('user_id')
    if db_user_is_admin(cur_user_id):
        if db_upd_user_role(user_id, 'R'):
            flash("L'utilisateur est maintenant un utilisateur régulier.")
        else:
            flash("Quelque chose n'a pas fonctionné.")
    else:
        flash("Vous n'êtes pas autorisé à changer le rôle d'un utilisateur.")
    return redirect(url_for('list_users'))


@app.route('/del_user/<int:user_id>', methods=['GET', 'POST'])
def del_user(user_id):
    if not logged_in():
        return redirect(url_for('login'))
    cur_user_id = session.get('user_id')
    if db_user_is_admin(cur_user_id):
        form = DelEntityForm()
        if form.validate_on_submit():
            app.logger.debug('Deleting a user')
            if db_del_user(user_id):
                flash("L'utilisateur a été effacé.")
            else:
                flash("Quelque chose n'a pas fonctionné.")
        else:
            user = db_user_by_id(user_id)
            if user:
                return render_template('del_user.html', form=form, user=user)
            else:
                flash("L'information n'a pas pu être retrouvée.")
    else:
        flash("Vous n'êtes pas autorisé à supprimer un utilisateur.")
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
            flash('Ce nom de note existe déjà. Veuillez en choisir un autre.')
            return render_template('add_secret.html', form=form)
        else:
            if db_add_secret(user_id, secret_name, secret_text):
                flash('La nouvelle note est ajoutée.')
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
            flash('Ce nom de note existe déjà. Veuillez en choisir un autre.')
            return render_template("upd_secret.html", form=form, secret=secret)
        if db_upd_secret(secret_id, secret_name, secret_text):
            flash("La note a été modifiée.")
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
            flash("La note a été effacée.")
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


@app.route('/list_servers')
def list_servers():
    if not logged_in():
        return redirect(url_for('login'))
    try:
        user_id = session.get('user_id')
        servers = Server.query.filter_by(user_id=user_id).order_by(Server.srvr_name).all()
        return render_template('list_servers.html', servers=servers)
    except Exception as e:
        flash("Quelque chose n'a pas fonctionné.")
        app.logger.error('Error: ' + str(e))
        abort(500)


@app.route('/show_server/<int:srvr_id>')
def show_server(srvr_id):
    if not logged_in():
        return redirect(url_for('login'))
    try:
        user_id = session.get('user_id')
        server = db_server_by_id(user_id, srvr_id)
        if server:
            return render_template("show_server.html", server=server)
        else:
            flash("L'information n'a pas pu être retrouvée.")
            return redirect(url_for('list_servers'))
    except Exception as e:
        flash("Quelque chose n'a pas fonctionné.")
        app.logger.error('Error: ' + str(e))
        abort(500)


@app.route('/add_server', methods=['GET', 'POST'])
def add_server():
    if not logged_in():
        return redirect(url_for('login'))
    app.logger.debug('Entering add_server')
    form = AddServerForm()
    if form.validate_on_submit():
        app.logger.debug('Inserting a new server')
        srvr_name = request.form['srvr_name']
        srvr_fqn = request.form['srvr_fqn']
        srvr_desc = request.form['srvr_desc']
        user_id = session.get('user_id')
        if db_server_exists(user_id, srvr_name):
            flash('Ce nom de serveur existe déjà. Veuillez en choisir un autre.')
            return render_template('add_server.html', form=form)
        else:
            if db_add_server(user_id, srvr_name, srvr_fqn, srvr_desc):
                flash('Le nouveau serveur est ajouté.')
                return redirect(url_for('list_servers'))
            else:
                flash('Une erreur de base de données est survenue.')
                abort(500)
    return render_template('add_server.html', form=form)


@app.route('/upd_server/<int:srvr_id>', methods=['GET', 'POST'])
def upd_server(srvr_id):
    if not logged_in():
        return redirect(url_for('login'))
    user_id = session.get('user_id')
    server = db_server_by_id(user_id, srvr_id)
    if server is None:
        flash("L'information n'a pas pu être retrouvée.")
        return redirect(url_for('list_servers'))
    form = UpdServerForm()
    if form.validate_on_submit():
        app.logger.debug('Updating a server')
        save_srvr_name = server.srvr_name
        srvr_name = form.srvr_name.data
        srvr_fqn = form.srvr_fqn.data
        srvr_desc = form.srvr_desc.data
        if (srvr_name != save_srvr_name) and db_server_exists(user_id, srvr_name):
            flash('Ce nom de serveur existe déjà. Veuillez en choisir un autre.')
            return render_template("upd_server.html", form=form, server=server)
        if db_upd_server(srvr_id, srvr_name, srvr_fqn, srvr_desc):
            flash("Le serveur a été modifié.")
        else:
            flash("Quelque chose n'a pas fonctionné.")
        return redirect(url_for('list_servers'))
    else:
        form.srvr_name.data = server.srvr_name
        form.srvr_fqn.data = server.srvr_fqn
        form.srvr_desc.data = server.srvr_desc
        return render_template("upd_server.html", form=form, server=server)


@app.route('/del_server/<int:srvr_id>', methods=['GET', 'POST'])
def del_server(srvr_id):
    if not logged_in():
        return redirect(url_for('login'))
    user_id = session.get('user_id')
    form = DelEntityForm()
    if form.validate_on_submit():
        app.logger.debug('Deleting a server')
        if db_del_server(srvr_id):
            flash("Le serveur a été effacé.")
        else:
            flash("Quelque chose n'a pas fonctionné.")
        return redirect(url_for('list_servers'))
    else:
        server = db_server_by_id(user_id, srvr_id)
        if server:
            return render_template('del_server.html', form=form, server=server)
        else:
            flash("L'information n'a pas pu être retrouvée.")
            return redirect(url_for('list_servers'))


@app.route('/list_srvr_accts/<int:srvr_id>')
def list_srvr_accts(srvr_id):
    if not logged_in():
        return redirect(url_for('login'))
    try:
        user_id = session.get('user_id')
        server = db_server_by_id(user_id, srvr_id)
        if server:
            session['srvr_id'] = srvr_id
            srvr_accts = ServerAccount.query.filter_by(srvr_id=srvr_id).order_by(ServerAccount.account_name).all()
            return render_template('list_srvr_accts.html', server=server, srvr_accts=srvr_accts)
        else:
            flash("L'information n'a pas pu être retrouvée.")
            return redirect(url_for('list_servers'))
    except Exception as e:
        flash("Quelque chose n'a pas fonctionné.")
        app.logger.error('Error: ' + str(e))
        abort(500)


@app.route('/show_srvr_acct/<int:srvr_acct_id>')
def show_srvr_acct(srvr_acct_id):
    if not logged_in():
        return redirect(url_for('login'))
    try:
        user_id = session.get('user_id')
        srvr_id = session.get('srvr_id')
        srvr_acct = db_srvr_acct_by_id(srvr_acct_id)
        if srvr_acct:
            server = db_server_by_id(user_id, srvr_acct.srvr_id)
            if server:
                return render_template("show_srvr_acct.html", srvr_acct=srvr_acct, server=server)
        flash("L'information n'a pas pu être retrouvée.")
        return redirect(url_for('list_srvr_acct', srvr_id=srvr_id))
    except Exception as e:
        flash("Quelque chose n'a pas fonctionné.")
        app.logger.error('Error: ' + str(e))
        abort(500)


@app.route('/add_srvr_acct', methods=['GET', 'POST'])
def add_srvr_acct():
    if not logged_in():
        return redirect(url_for('login'))
    srvr_id = session.get('srvr_id')
    app.logger.debug('Entering add_srvr_acct')
    form = AddSrvrAcctForm()
    if form.validate_on_submit():
        app.logger.debug('Inserting a new server')
        account_name = request.form['account_name']
        account_pass = request.form['account_pass']
        account_desc = request.form['account_desc']
        if db_srvr_acct_exists(srvr_id, account_name):
            flash('Ce nom de compte existe déjà sur le serveur. Veuillez en choisir un autre.')
            return render_template('add_srvr_acct.html', form=form, srvr_id=srvr_id)
        else:
            if db_add_srvr_acct(srvr_id, account_name, account_pass, account_desc):
                flash('Le nouveau compte est ajouté.')
                return redirect(url_for('list_srvr_accts', srvr_id=srvr_id))
            else:
                flash('Une erreur de base de données est survenue.')
                abort(500)
    return render_template('add_srvr_acct.html', form=form, srvr_id=srvr_id)


@app.route('/upd_srvr_acct/<int:srvr_acct_id>', methods=['GET', 'POST'])
def upd_srvr_acct(srvr_acct_id):
    if not logged_in():
        return redirect(url_for('login'))
    user_id = session.get('user_id')
    srvr_id = session.get('srvr_id')
    srvr_acct = db_srvr_acct_by_id(srvr_acct_id)
    if srvr_acct is None:
        flash("L'information n'a pas pu être retrouvée.")
        return redirect(url_for('list_srvr_accts', srvr_id=srvr_id))
    # Get the parent server to validate that the server account belongs to the user
    server = db_server_by_id(user_id, srvr_acct.srvr_id)
    if server is None:
        flash("L'information n'a pas pu être retrouvée.")
        return redirect(url_for('list_srvr_accts', srvr_id=srvr_id))
    form = UpdSrvrAcctForm()
    if form.validate_on_submit():
        app.logger.debug('Updating a server account')
        save_account_name = srvr_acct.account_name
        account_name = form.account_name.data
        account_desc = form.account_desc.data
        account_pass = form.account_pass.data
        if (account_name != save_account_name) and db_srvr_acct_exists(srvr_id, account_name):
            flash('Ce nom de compte existe déjà. Veuillez en choisir un autre.')
            return render_template("upd_srvr_acct.html", form=form, server=server)
        if db_upd_srvr_acct(srvr_acct_id, account_name, account_pass, account_desc):
            flash("Le compte a été modifié.")
        else:
            flash("Quelque chose n'a pas fonctionné.")
        return redirect(url_for('list_srvr_accts', srvr_id=srvr_id))
    else:
        form.account_name.data = srvr_acct.account_name
        form.account_pass.data = srvr_acct.account_pass
        form.account_desc.data = srvr_acct.account_desc
        return render_template("upd_srvr_acct.html", form=form, server=server)


@app.route('/del_srvr_acct/<int:srvr_acct_id>', methods=['GET', 'POST'])
def del_srvr_acct(srvr_acct_id):
    if not logged_in():
        return redirect(url_for('login'))
    user_id = session.get('user_id')
    srvr_id = session.get('srvr_id')
    form = DelEntityForm()
    if form.validate_on_submit():
        app.logger.debug('Deleting a srvr_account')
        if db_del_srvr_acct(srvr_acct_id):
            flash("Le compte a été effacé.")
        else:
            flash("Quelque chose n'a pas fonctionné.")
        return redirect(url_for('list_srvr_accts', srvr_id=srvr_id))
    else:
        srvr_acct = db_srvr_acct_by_id(srvr_acct_id)
        if srvr_acct:
            server = db_server_by_id(user_id, srvr_acct.srvr_id)
            if server:
                return render_template('del_srvr_acct.html', form=form, srvr_acct=srvr_acct, server=server)
        flash("L'information n'a pas pu être retrouvée.")
        return redirect(url_for('list_srvr_accts', srvr_id=srvr_id))


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
            user.user_role = 'SuperAdmin'
        else:
            user.user_role = 'Régulier'
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


def db_upd_user_role(user_id, user_role):
    try:
        user = AppUser.query.get(user_id)
        if user_role == 'A':
            user.user_role = 'Admin'
        else:
            user.user_role = 'Régulier'
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


def db_user_is_admin(user_id):
    app.logger.debug('Entering db_user_is_admin with: ' + str(user_id))
    try:
        user = AppUser.query.get(user_id)
        if user is None:
            return False
        else:
            if user.user_role in ['Admin', 'SuperAdmin']:
                return True
            else:
                return False
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
            flash("Mot de passe inchangé. L'utilisateur n'a pas été retrouvé.")
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
            flash("L'utilisateur n'existe pas.")
            return False

        if not user.activated_ts:
            flash("L'utilisateur n'est pas activé.")
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


# DB functions for Secret: exists, by_id, add, upd, del, others
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


# DB functions for Server: exists, by_id, add, upd, del, others
def db_server_exists(user_id, srvr_name):
    app.logger.debug('Entering server_exists with: ' + srvr_name)
    try:
        server = Server.query.filter_by(user_id=user_id, srvr_name=srvr_name).first()
        if server is None:
            return False
        else:
            return True
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return False


def db_server_by_id(user_id, srvr_id):
    try:
        server = Server.query.filter_by(srvr_id=srvr_id, user_id=user_id).first()
        if server:
            return server
        else:
            return None
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return None


def db_add_server(user_id, srvr_name, srvr_fqn, srvr_desc):
    server = Server(user_id, srvr_name, srvr_fqn, srvr_desc)
    try:
        db.session.add(server)
        db.session.commit()
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return False
    return True


def db_upd_server(srvr_id, srvr_name, srvr_fqn, srvr_desc):
    try:
        server = Server.query.get(srvr_id)
        server.srvr_name = srvr_name
        server.srvr_fqn = srvr_fqn
        server.srvr_desc = srvr_desc
        db.session.commit()
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return False
    return True


def db_del_server(srvr_id):
    try:
        server = Server.query.get(srvr_id)
        for srvr_acc in server.srvr_accounts:
            db.session.delete(srvr_acc)
        db.session.delete(server)
        db.session.commit()
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return False
    return True


# DB functions for ServerAccount: exists, by_id, add, upd, del, others
def db_srvr_acct_exists(srvr_id, account_name):
    app.logger.debug('Entering srvr_acct_exists with: ' + account_name)
    try:
        srvr_acct = ServerAccount.query.filter_by(srvr_id=srvr_id, account_name=account_name).first()
        if srvr_acct is None:
            return False
        else:
            return True
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return False


def db_srvr_acct_by_id(srvr_acct_id):
    try:
        srvr_acct = ServerAccount.query.filter_by(srvr_acct_id=srvr_acct_id).first()
        if srvr_acct:
            srvr_acct.account_pass = decrypt_message(srvr_acct.account_pass)
            return srvr_acct
        else:
            return None
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return None


def db_add_srvr_acct(srvr_id, account_name, account_pass, account_desc):
    account_pass = encrypt_message(account_pass)
    srvr_acct = ServerAccount(srvr_id, account_name, account_pass, account_desc)
    try:
        db.session.add(srvr_acct)
        db.session.commit()
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return False
    return True


def db_upd_srvr_acct(srvr_acct_id, account_name, account_pass, account_desc):
    try:
        srvr_acct = ServerAccount.query.get(srvr_acct_id)
        srvr_acct.account_name = account_name
        srvr_acct.account_pass = encrypt_message(account_pass)
        srvr_acct.account_desc = account_desc
        db.session.commit()
    except Exception as e:
        app.logger.error('Error: ' + str(e))
        return False
    return True


def db_del_srvr_acct(srvr_acct_id):
    try:
        srvr_acct = ServerAccount.query.get(srvr_acct_id)
        db.session.delete(srvr_acct)
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
