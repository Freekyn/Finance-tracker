from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

# 1. INITIALIZE EXTENSIONS
db = SQLAlchemy()
login_manager = LoginManager()

# 2. DEFINE MODELS
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    expenses = db.relationship('Transaction', backref='user', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(20), nullable=False) # 'Income' or 'Expense'
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'amount': self.amount,
            'type': self.type,
            'category': self.category,
            'description': self.description,
            'date': self.date.isoformat()
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 3. CREATE APP
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dev-key-change-this-in-prod'
    database_url = os.environ.get('DATABASE_URL', 'sqlite:///finance.db')
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
        
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    with app.app_context():
        db.create_all()

    return app

app = create_app()

# 4. ROUTES

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'User already exists'}), 400
    
    hashed_pw = generate_password_hash(data['password'], method='scrypt')
    new_user = User(username=data['username'], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created!'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        user = User.query.filter_by(username=data['username']).first()
        if user and check_password_hash(user.password, data['password']):
            login_user(user)
            return jsonify({'message': 'Logged in successfully'})
        return jsonify({'error': 'Invalid credentials'}), 401
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

# --- API ROUTES ---

@app.route('/api/transactions', methods=['GET', 'POST'])
@login_required
def manage_transactions():
    if request.method == 'POST':
        data = request.json
        new_tx = Transaction(
            amount=data.get('amount'),
            type=data.get('type', 'Expense'), # Default to Expense if not specified
            category=data.get('category'),
            description=data.get('description'),
            user_id=current_user.id
        )
        db.session.add(new_tx)
        db.session.commit()
        return jsonify({'message': 'Transaction added', 'transaction': new_tx.to_dict()})
    
    # GET: Return all transactions sorted by date
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date.desc()).all()
    return jsonify([t.to_dict() for t in transactions])

@app.route('/api/transactions/<int:id>', methods=['PUT', 'DELETE'])
@login_required
def update_transaction(id):
    tx = Transaction.query.get_or_404(id)
    if tx.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'DELETE':
        db.session.delete(tx)
        db.session.commit()
        return jsonify({'message': 'Deleted'})

    if request.method == 'PUT':
        data = request.json
        tx.amount = data.get('amount', tx.amount)
        tx.category = data.get('category', tx.category)
        tx.description = data.get('description', tx.description)
        tx.type = data.get('type', tx.type)
        db.session.commit()
        return jsonify({'message': 'Updated'})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)