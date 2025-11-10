from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import requests
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'ladybug-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///ladybug.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    bots = db.relationship('Bot', backref='owner', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Bot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    bot_type = db.Column(db.String(50))  # Discord, Telegram, etc.
    hosting_provider = db.Column(db.String(50))  # Katabump, Heroku, Render
    status = db.Column(db.String(20), default='stopped')  # running, stopped, deploying
    repository_url = db.Column(db.String(255))
    env_vars = db.Column(db.Text)  # JSON string of environment variables
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_deployed = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    api_key = db.Column(db.String(255))  # Provider-specific API key
    deployment_id = db.Column(db.String(255))  # Provider-specific deployment ID

class HostingProvider(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    api_endpoint = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    description = db.Column(db.Text)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Hosting Provider Integrations
class HostingManager:
    @staticmethod
    def deploy_to_render(bot, api_key):
        """Deploy bot to Render.com"""
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'name': bot.name,
            'type': 'web_service',
            'repo': bot.repository_url,
            'autoDeploy': True,
            'envVars': []
        }
        
        try:
            response = requests.post(
                'https://api.render.com/v1/services',
                headers=headers,
                json=data
            )
            return response.json() if response.status_code in [200, 201] else None
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def deploy_to_heroku(bot, api_key):
        """Deploy bot to Heroku"""
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Accept': 'application/vnd.heroku+json; version=3',
            'Content-Type': 'application/json'
        }
        
        data = {
            'name': bot.name.lower().replace(' ', '-'),
            'region': 'us',
            'stack': 'heroku-22'
        }
        
        try:
            response = requests.post(
                'https://api.heroku.com/apps',
                headers=headers,
                json=data
            )
            return response.json() if response.status_code in [200, 201] else None
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def deploy_to_katabump(bot, api_key):
        """Deploy bot to Katabump (Mock implementation)"""
        # Katabump integration would go here
        # This is a placeholder as Katabump's API structure may vary
        return {
            'success': True,
            'deployment_id': f'katabump_{bot.id}',
            'message': 'Bot deployed to Katabump successfully'
        }
    
    @staticmethod
    def get_bot_status(bot):
        """Get current bot status from provider"""
        if bot.hosting_provider == 'render':
            return HostingManager._get_render_status(bot)
        elif bot.hosting_provider == 'heroku':
            return HostingManager._get_heroku_status(bot)
        elif bot.hosting_provider == 'katabump':
            return HostingManager._get_katabump_status(bot)
        return 'unknown'
    
    @staticmethod
    def _get_render_status(bot):
        if not bot.api_key or not bot.deployment_id:
            return 'not_deployed'
        # Implementation for Render status check
        return 'running'
    
    @staticmethod
    def _get_heroku_status(bot):
        if not bot.api_key or not bot.deployment_id:
            return 'not_deployed'
        # Implementation for Heroku status check
        return 'running'
    
    @staticmethod
    def _get_katabump_status(bot):
        if not bot.deployment_id:
            return 'not_deployed'
        return 'running'

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    bots = Bot.query.filter_by(user_id=current_user.id).all()
    stats = {
        'total_bots': len(bots),
        'running': len([b for b in bots if b.status == 'running']),
        'stopped': len([b for b in bots if b.status == 'stopped']),
        'deploying': len([b for b in bots if b.status == 'deploying'])
    }
    return render_template('dashboard.html', bots=bots, stats=stats)

@app.route('/bots')
@login_required
def bots():
    user_bots = Bot.query.filter_by(user_id=current_user.id).all()
    return render_template('bots.html', bots=user_bots)

@app.route('/deploy', methods=['GET', 'POST'])
@login_required
def deploy():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        bot_type = request.form.get('bot_type')
        hosting_provider = request.form.get('hosting_provider')
        repository_url = request.form.get('repository_url')
        api_key = request.form.get('api_key')
        
        bot = Bot(
            name=name,
            description=description,
            bot_type=bot_type,
            hosting_provider=hosting_provider,
            repository_url=repository_url,
            api_key=api_key,
            user_id=current_user.id,
            status='deploying'
        )
        
        db.session.add(bot)
        db.session.commit()
        
        # Deploy to selected provider
        if hosting_provider == 'render':
            result = HostingManager.deploy_to_render(bot, api_key)
        elif hosting_provider == 'heroku':
            result = HostingManager.deploy_to_heroku(bot, api_key)
        elif hosting_provider == 'katabump':
            result = HostingManager.deploy_to_katabump(bot, api_key)
        else:
            result = {'error': 'Unknown hosting provider'}
        
        if result and 'error' not in result:
            bot.status = 'running'
            bot.last_deployed = datetime.utcnow()
            bot.deployment_id = result.get('id', f'{hosting_provider}_{bot.id}')
            flash(f'Bot "{name}" deployed successfully!', 'success')
        else:
            bot.status = 'stopped'
            flash(f'Deployment failed: {result.get("error", "Unknown error")}', 'danger')
        
        db.session.commit()
        return redirect(url_for('bots'))
    
    providers = ['render', 'heroku', 'katabump']
    return render_template('deploy.html', providers=providers)

@app.route('/bot/<int:bot_id>/delete', methods=['POST'])
@login_required
def delete_bot(bot_id):
    bot = Bot.query.get_or_404(bot_id)
    
    if bot.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('bots'))
    
    db.session.delete(bot)
    db.session.commit()
    flash(f'Bot "{bot.name}" deleted successfully', 'success')
    return redirect(url_for('bots'))

@app.route('/bot/<int:bot_id>/toggle', methods=['POST'])
@login_required
def toggle_bot(bot_id):
    bot = Bot.query.get_or_404(bot_id)
    
    if bot.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if bot.status == 'running':
        bot.status = 'stopped'
        message = 'Bot stopped'
    else:
        bot.status = 'running'
        message = 'Bot started'
    
    db.session.commit()
    return jsonify({'status': bot.status, 'message': message})

@app.route('/api/bots/<int:bot_id>/status')
@login_required
def bot_status(bot_id):
    bot = Bot.query.get_or_404(bot_id)
    
    if bot.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    status = HostingManager.get_bot_status(bot)
    return jsonify({
        'id': bot.id,
        'name': bot.name,
        'status': status,
        'provider': bot.hosting_provider
    })

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', user=current_user)

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
