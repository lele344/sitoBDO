import os
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv  # Per caricare variabili d'ambiente da .env

# Carica le variabili d'ambiente
load_dotenv()

app = Flask(__name__)

# Configurazione Sicura
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')  # Usa PostgreSQL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'chiave_segreta_default')

# Inizializza il database
db = SQLAlchemy(app)

# Configura Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Definizione Modello Utenti
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    badges = db.Column(db.String(200), default='')
    points = db.Column(db.Integer, default=0)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Route Homepage
@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user)

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password_hash, password):
            return render_template('login.html', error='Credenziali non valide')

        login_user(user)
        return redirect(url_for('index'))

    return render_template('login.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Admin - Lista Utenti
@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin_users.html', users=users)

# Aggiungi Utente
@app.route('/admin/user/add', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        return jsonify(success=False, message="Non autorizzato"), 403

    data = request.json
    if not data:
        return jsonify(success=False, message="Dati non validi"), 400

    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')

    if not username or not password:
        return jsonify(success=False, message="Username e password sono obbligatori"), 400

    if User.query.filter_by(username=username).first():
        return jsonify(success=False, message="Username già esistente"), 400

    password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
    new_user = User(username=username, password_hash=password_hash, role=role)
    db.session.add(new_user)
    db.session.commit()

    return jsonify(success=True, message="Utente aggiunto con successo"), 201

# Elimina Utente
@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return jsonify(success=False, message="Non autorizzato"), 403

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify(success=True, message="Utente eliminato con successo")
    else:
        return jsonify(success=False, message="Utente non trovato"), 404

# Creazione delle tabelle al primo avvio
with app.app_context():
    db.create_all()

# Avvio dell'app in produzione con Gunicorn
if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
