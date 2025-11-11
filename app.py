from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import requests
import json
from functools import wraps
import secrets

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///ladybug.db')

# Fix for Heroku postgres URL
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# Session configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# ============================================================================
# DATABASE MODELS
# ============================================================================

class User(UserMixin, db.Model):
    """User model for authentication and account management"""
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    
    # Relationships
    bots = db.relationship('Bot', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set user password"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    def get_bot_count(self):
        """Get total number of bots owned by user"""
        return self.bots.count()
    
    def get_running_bots(self):
        """Get count of running bots"""
        return self.bots.filter_by(status='running').count()
    
    def __repr__(self):
        return f'<User {self.username}>'


class Bot(db.Model):
    """Bot model for managing deployed bots"""
    __tablename__ = 'bot'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    bot_type = db.Column(db.String(50), nullable=False)  # Discord, Telegram, Slack, etc.
    hosting_provider = db.Column(db.String(50), nullable=False)  # Render, Heroku, Katabump
    status = db.Column(db.String(20), default='stopped')  # running, stopped, deploying, error
    repository_url = db.Column(db.String(255))
    env_vars = db.Column(db.Text)  # JSON string of environment variables
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_deployed = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    api_key = db.Column(db.String(255))  # Encrypted provider API key
    deployment_id = db.Column(db.String(255))  # Provider-specific deployment ID
    error_message = db.Column(db.Text)  # Last error message if deployment failed
    
    def set_env_vars(self, env_dict):
        """Store environment variables as JSON"""
        self.env_vars = json.dumps(env_dict)
    
    def get_env_vars(self):
        """Retrieve environment variables as dictionary"""
        if self.env_vars:
            try:
                return json.loads(self.env_vars)
            except json.JSONDecodeError:
                return {}
        return {}
    
    def update_status(self, status, error_message=None):
        """Update bot status and error message"""
        self.status = status
        self.error_message = error_message
        self.updated_at = datetime.utcnow()
        db.session.commit()
    
    def __repr__(self):
        return f'<Bot {self.name} - {self.status}>'


class HostingProvider(db.Model):
    """Hosting provider configuration"""
    __tablename__ = 'hosting_provider'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    display_name = db.Column(db.String(100))
    api_endpoint = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    description = db.Column(db.Text)
    documentation_url = db.Column(db.String(255))
    
    def __repr__(self):
        return f'<HostingProvider {self.name}>'


class ActivityLog(db.Model):
    """Log user and bot activities"""
    __tablename__ = 'activity_log'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    bot_id = db.Column(db.Integer, db.ForeignKey('bot.id'))
    action = db.Column(db.String(50), nullable=False)  # deploy, stop, start, delete
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f'<ActivityLog {self.action} - {self.timestamp}>'


# ============================================================================
# LOGIN MANAGER
# ============================================================================

@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    return User.query.get(int(user_id))


# ============================================================================
# HOSTING PROVIDER MANAGER
# ============================================================================

class HostingManager:
    """Manager for hosting provider integrations"""
    
    @staticmethod
    def deploy_to_render(bot, api_key):
        """Deploy bot to Render.com"""
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        env_vars = bot.get_env_vars()
        env_list = [{'key': k, 'value': v} for k, v in env_vars.items()]
        
        data = {
            'type': 'background_worker',
            'name': bot.name.lower().replace(' ', '-'),
            'repo': bot.repository_url,
            'autoDeploy': True,
            'branch': 'main',
            'envVars': env_list
        }
        
        try:
            response = requests.post(
                'https://api.render.com/v1/services',
                headers=headers,
                json=data,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                result = response.json()
                return {
                    'success': True,
                    'id': result.get('service', {}).get('id'),
                    'message': 'Successfully deployed to Render'
                }
            else:
                return {
                    'success': False,
                    'error': f"Render API error: {response.status_code}"
                }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f"Connection error: {str(e)}"
            }
    
    @staticmethod
    def deploy_to_heroku(bot, api_key):
        """Deploy bot to Heroku"""
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Accept': 'application/vnd.heroku+json; version=3',
            'Content-Type': 'application/json'
        }
        
        app_name = bot.name.lower().replace(' ', '-')
        
        # Create app
        data = {
            'name': app_name,
            'region': 'us',
            'stack': 'heroku-22'
        }
        
        try:
            response = requests.post(
                'https://api.heroku.com/apps',
                headers=headers,
                json=data,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                result = response.json()
                app_id = result.get('id')
                
                # Set environment variables
                env_vars = bot.get_env_vars()
                if env_vars:
                    requests.patch(
                        f'https://api.heroku.com/apps/{app_id}/config-vars',
                        headers=headers,
                        json=env_vars,
                        timeout=30
                    )
                
                return {
                    'success': True,
                    'id': app_id,
                    'message': 'Successfully deployed to Heroku'
                }
            else:
                return {
                    'success': False,
                    'error': f"Heroku API error: {response.status_code}"
                }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f"Connection error: {str(e)}"
            }
    
    @staticmethod
    def deploy_to_katabump(bot, api_key):
        """Deploy bot to Katabump (Mock implementation - update with actual API)"""
        # This is a placeholder. Update with actual Katabump API endpoints
        try:
            deployment_id = f'katabump_{bot.id}_{secrets.token_hex(8)}'
            return {
                'success': True,
                'id': deployment_id,
                'message': 'Successfully deployed to Katabump'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f"Katabump deployment error: {str(e)}"
            }
    
    @staticmethod
    def deploy_bot(bot, api_key):
        """Deploy bot to the specified hosting provider"""
        if bot.hosting_provider == 'render':
            return HostingManager.deploy_to_render(bot, api_key)
        elif bot.hosting_provider == 'heroku':
            return HostingManager.deploy_to_heroku(bot, api_key)
        elif bot.hosting_provider == 'katabump':
            return HostingManager.deploy_to_katabump(bot, api_key)
        else:
            return {
                'success': False,
                'error': 'Unknown hosting provider'
            }
    
    @staticmethod
    def get_bot_status(bot):
        """Get current bot status from provider"""
        if not bot.deployment_id:
            return 'not_deployed'
        
        if bot.hosting_provider == 'render':
            return HostingManager._get_render_status(bot)
        elif bot.hosting_provider == 'heroku':
            return HostingManager._get_heroku_status(bot)
        elif bot.hosting_provider == 'katabump':
            return HostingManager._get_katabump_status(bot)
        
        return bot.status
    
    @staticmethod
    def _get_render_status(bot):
        """Get Render service status"""
        if not bot.api_key or not bot.deployment_id:
            return 'not_deployed'
        
        try:
            headers = {'Authorization': f'Bearer {bot.api_key}'}
            response = requests.get(
                f'https://api.render.com/v1/services/{bot.deployment_id}',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                service_status = data.get('service', {}).get('serviceDetails', {}).get('state')
                return 'running' if service_status == 'running' else 'stopped'
        except:
            pass
        
        return bot.status
    
    @staticmethod
    def _get_heroku_status(bot):
        """Get Heroku app status"""
        if not bot.api_key or not bot.deployment_id:
            return 'not_deployed'
        
        try:
            headers = {
                'Authorization': f'Bearer {bot.api_key}',
                'Accept': 'application/vnd.heroku+json; version=3'
            }
            response = requests.get(
                f'https://api.heroku.com/apps/{bot.deployment_id}',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return 'running'
        except:
            pass
        
        return bot.status
    
    @staticmethod
    def _get_katabump_status(bot):
        """Get Katabump service status"""
        if not bot.deployment_id:
            return 'not_deployed'
        # Implement actual Katabump status check
        return bot.status
    
    @staticmethod
    def stop_bot(bot):
        """Stop a running bot"""
        if bot.hosting_provider == 'heroku':
            return HostingManager._stop_heroku_bot(bot)
        elif bot.hosting_provider == 'render':
            return HostingManager._stop_render_bot(bot)
        elif bot.hosting_provider == 'katabump':
            return HostingManager._stop_katabump_bot(bot)
        return {'success': False, 'error': 'Provider not supported'}
    
    @staticmethod
    def _stop_heroku_bot(bot):
        """Stop Heroku dyno"""
        try:
            headers = {
                'Authorization': f'Bearer {bot.api_key}',
                'Accept': 'application/vnd.heroku+json; version=3'
            }
            response = requests.post(
                f'https://api.heroku.com/apps/{bot.deployment_id}/dynos/worker',
                headers=headers,
                json={'quantity': 0},
                timeout=10
            )
            return {'success': response.status_code == 200}
        except:
            return {'success': False}
    
    @staticmethod
    def _stop_render_bot(bot):
        """Stop Render service"""
        # Implement Render stop logic
        return {'success': True}
    
    @staticmethod
    def _stop_katabump_bot(bot):
        """Stop Katabump service"""
        # Implement Katabump stop logic
        return {'success': True}


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def log_activity(action, user_id=None, bot_id=None, details=None):
    """Log user/bot activity"""
    try:
        log = ActivityLog(
            user_id=user_id or (current_user.id if current_user.is_authenticated else None),
            bot_id=bot_id,
            action=action,
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Failed to log activity: {str(e)}")


def admin_required(f):
    """Decorator to require admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# ROUTES - PUBLIC
# ============================================================================

@app.route('/')
def index():
    """Homepage"""
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        errors = []
        
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters long')
        
        if not email or '@' not in email:
            errors.append('Invalid email address')
        
        if not password or len(password) < 6:
            errors.append('Password must be at least 6 characters long')
        
        if password != confirm_password:
            errors.append('Passwords do not match')
        
        if User.query.filter_by(username=username).first():
            errors.append('Username already exists')
        
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered')
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('register.html')
        
        # Create user
        try:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            log_activity('register', user_id=user.id, details=f'New user registered: {username}')
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration. Please try again.', 'danger')
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember_me') == 'on'
        
        if not username or not password:
            flash('Please provide username and password', 'danger')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('Your account has been deactivated', 'danger')
                return render_template('login.html')
            
            login_user(user, remember=remember)
            user.update_last_login()
            
            log_activity('login', user_id=user.id)
            
            flash(f'Welcome back, {user.username}!', 'success')
            
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            log_activity('failed_login', details=f'Failed login attempt for: {username}')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """User logout"""
    log_activity('logout')
    logout_user()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('index'))


# ============================================================================
# ROUTES - AUTHENTICATED
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    bots = Bot.query.filter_by(user_id=current_user.id).all()
    
    stats = {
        'total_bots': len(bots),
        'running': len([b for b in bots if b.status == 'running']),
        'stopped': len([b for b in bots if b.status == 'stopped']),
        'deploying': len([b for b in bots if b.status == 'deploying']),
        'error': len([b for b in bots if b.status == 'error'])
    }
    
    recent_activities = ActivityLog.query.filter_by(user_id=current_user.id)\
        .order_by(ActivityLog.timestamp.desc())\
        .limit(10)\
        .all()
    
    return render_template('dashboard.html', 
                         bots=bots, 
                         stats=stats,
                         recent_activities=recent_activities)


@app.route('/bots')
@login_required
def bots():
    """List all user bots"""
    user_bots = Bot.query.filter_by(user_id=current_user.id)\
        .order_by(Bot.created_at.desc())\
        .all()
    return render_template('bots.html', bots=user_bots)


@app.route('/bot/<int:bot_id>')
@login_required
def bot_detail(bot_id):
    """View bot details"""
    bot = Bot.query.get_or_404(bot_id)
    
    if bot.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('bots'))
    
    activities = ActivityLog.query.filter_by(bot_id=bot_id)\
        .order_by(ActivityLog.timestamp.desc())\
        .limit(20)\
        .all()
    
    return render_template('bot_detail.html', bot=bot, activities=activities)


@app.route('/deploy', methods=['GET', 'POST'])
@login_required
def deploy():
    """Deploy new bot"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        bot_type = request.form.get('bot_type')
        hosting_provider = request.form.get('hosting_provider')
        repository_url = request.form.get('repository_url', '').strip()
        api_key = request.form.get('api_key', '').strip()
        
        # Validation
        if not all([name, bot_type, hosting_provider]):
            flash('Please fill in all required fields', 'danger')
            return redirect(url_for('deploy'))
        
        # Create bot
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
        
        # Parse environment variables
        env_vars = {}
        env_keys = request.form.getlist('env_key[]')
        env_values = request.form.getlist('env_value[]')
        
        for key, value in zip(env_keys, env_values):
            if key.strip():
                env_vars[key.strip()] = value.strip()
        
        bot.set_env_vars(env_vars)
        
        try:
            db.session.add(bot)
            db.session.commit()
            
            # Deploy to provider
            result = HostingManager.deploy_bot(bot, api_key)
            
            if result.get('success'):
                bot.status = 'running'
                bot.last_deployed = datetime.utcnow()
                bot.deployment_id = result.get('id')
                bot.error_message = None
                
                log_activity('deploy', bot_id=bot.id, details=f'Deployed bot: {name}')
                flash(f'Bot "{name}" deployed successfully!', 'success')
            else:
                bot.status = 'error'
                bot.error_message = result.get('error', 'Unknown deployment error')
                
                log_activity('deploy_failed', bot_id=bot.id, details=bot.error_message)
                flash(f'Deployment failed: {bot.error_message}', 'danger')
            
            db.session.commit()
            return redirect(url_for('bot_detail', bot_id=bot.id))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Deployment error: {str(e)}")
            flash(f'An error occurred during deployment: {str(e)}', 'danger')
    
    providers = [
        {'id': 'render', 'name': 'Render', 'description': 'Free tier available, easy setup'},
        {'id': 'heroku', 'name': 'Heroku', 'description': 'Popular platform, good documentation'},
        {'id': 'katabump', 'name': 'Katabump', 'description': 'Specialized bot hosting'}
    ]
    
    bot_types = [
        {'id': 'discord', 'name': 'Discord Bot'},
        {'id': 'telegram', 'name': 'Telegram Bot'},
        {'id': 'slack', 'name': 'Slack Bot'},
        {'id': 'whatsapp', 'name': 'WhatsApp Bot'},
        {'id': 'other', 'name': 'Other'}
    ]
    
    return render_template('deploy.html', providers=providers, bot_types=bot_types)


@app.route('/bot/<int:bot_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_bot(bot_id):
    """Edit bot configuration"""
    bot = Bot.query.get_or_404(bot_id)
    
    if bot.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('bots'))
    
    if request.method == 'POST':
        bot.name = request.form.get('name', '').strip()
        bot.description = request.form.get('description', '').strip()
        bot.repository_url = request.form.get('repository_url', '').strip()
        
        # Update environment variables
        env_vars = {}
        env_keys = request.form.getlist('env_key[]')
        env_values = request.form.getlist('env_value[]')
        
        for key, value in zip(env_keys, env_values):
            if key.strip():
                env_vars[key.strip()] = value.strip()
        
        bot.set_env_vars(env_vars)
        bot.updated_at = datetime.utcnow()
        
        try:
            db.session.commit()
            log_activity('edit', bot_id=bot.id, details=f'Updated bot: {bot.name}')
            flash('Bot updated successfully', 'success')
            return redirect(url_for('bot_detail', bot_id=bot.id))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Edit error: {str(e)}")
            flash('An error occurred while updating the bot', 'danger')
    
    return render_template('edit_bot.html', bot=bot, env_vars=bot.get_env_vars())


@app.route('/bot/<int:bot_id>/delete', methods=['POST'])
@login_required
def delete_bot(bot_id):
    """Delete bot"""
    bot = Bot.query.get_or_404(bot_id)
    
    if bot.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('bots'))
    
    try:
        bot_name = bot.name
        db.session.delete(bot)
        db.session.commit()
        
        log_activity('delete', details=f'Deleted bot: {bot_name}')
        flash(f'Bot "{bot_name}" deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Delete error: {str(e)}")
        flash('An error occurred while deleting the bot', 'danger')
    
    return redirect(url_for('bots'))


@app.route('/bot/<int:bot_id>/toggle', methods=['POST'])
@login_required
def toggle_bot(bot_id):
    """Start or stop bot"""
    bot = Bot.query.get_or_404(bot_id)
    
    if bot.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        if bot.status == 'running':
            result = HostingManager.stop_bot(bot)
            if result.get('success'):
                bot.status = 'stopped'
                message = 'Bot stopped successfully'
                action = 'stop'
            else:
                return jsonify({'error': 'Failed to stop bot'}), 500
        else:
            # Restart/start bot
            result = HostingManager.deploy_bot(bot, bot.api_key)
            if result.get('success'):
                bot.status = 'running'
                bot.last_deployed = datetime.utcnow()
                message = 'Bot started successfully'
                action = 'start'
            else:
                bot.status = 'error'
                bot.error_message = result.get('error')
                db.session.commit()
                return jsonify({'error': result.get('error')}), 500
        
        db.session.commit()
        log_activity(action, bot_id=bot.id, details=message)
        
        return jsonify({
            'success': True,
            'status': bot.status,
            'message': message
        })
    except Exception as e:
        app.logger.error(f"Toggle error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/bot/<int:bot_id>/restart', methods=['POST'])
@login_required
def restart_bot(bot_id):
    """Restart bot"""
    bot = Bot.query.get_or_404(bot_id)
    
    if bot.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        # Stop first
        HostingManager.stop_bot(bot)
        bot.status = 'deploying'
        db.session.commit()
        
        # Redeploy
        result = HostingManager.deploy_bot(bot, bot.api_key)
        
        if result.get('success'):
            bot.status = 'running'
            bot.last_deployed = datetime.utcnow()
            bot.error_message = None
            message = 'Bot restarted successfully'
            
            log_activity('restart', bot_id=bot.id, details=message)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'status': bot.status,
                'message': message
            })
        else:
            bot.status = 'error'
            bot.error_message = result.get('error')
            db.session.commit()
            return jsonify({'error': result.get('error')}), 500
            
    except Exception as e:
        app.logger.error(f"Restart error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/bot/<int:bot_id>/logs')
@login_required
def bot_logs(bot_id):
    """View bot logs"""
    bot = Bot.query.get_or_404(bot_id)
    
    if bot.user_id != current_user.id:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('bots'))
    
    # Get activity logs for this bot
    logs = ActivityLog.query.filter_by(bot_id=bot_id)\
        .order_by(ActivityLog.timestamp.desc())\
        .limit(100)\
        .all()
    
    return render_template('bot_logs.html', bot=bot, logs=logs)


# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/api/bots/<int:bot_id>/status')
@login_required
def api_bot_status(bot_id):
    """API endpoint to get bot status"""
    bot = Bot.query.get_or_404(bot_id)
    
    if bot.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        status = HostingManager.get_bot_status(bot)
        
        # Update status in database if different
        if status != bot.status and status != 'not_deployed':
            bot.status = status
            db.session.commit()
        
        return jsonify({
            'id': bot.id,
            'name': bot.name,
            'status': status,
            'provider': bot.hosting_provider,
            'last_deployed': bot.last_deployed.isoformat() if bot.last_deployed else None,
            'error_message': bot.error_message
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats')
@login_required
def api_stats():
    """API endpoint for dashboard statistics"""
    bots = Bot.query.filter_by(user_id=current_user.id).all()
    
    stats = {
        'total_bots': len(bots),
        'running': len([b for b in bots if b.status == 'running']),
        'stopped': len([b for b in bots if b.status == 'stopped']),
        'deploying': len([b for b in bots if b.status == 'deploying']),
        'error': len([b for b in bots if b.status == 'error']),
        'last_login': current_user.last_login.isoformat() if current_user.last_login else None,
        'member_since': current_user.created_at.isoformat()
    }
    
    return jsonify(stats)


@app.route('/api/bots')
@login_required
def api_bots():
    """API endpoint to list all user bots"""
    bots = Bot.query.filter_by(user_id=current_user.id).all()
    
    bots_data = []
    for bot in bots:
        bots_data.append({
            'id': bot.id,
            'name': bot.name,
            'description': bot.description,
            'bot_type': bot.bot_type,
            'hosting_provider': bot.hosting_provider,
            'status': bot.status,
            'created_at': bot.created_at.isoformat(),
            'last_deployed': bot.last_deployed.isoformat() if bot.last_deployed else None
        })
    
    return jsonify({'bots': bots_data})


# ============================================================================
# SETTINGS & PROFILE ROUTES
# ============================================================================

@app.route('/settings')
@login_required
def settings():
    """User settings page"""
    return render_template('settings.html', user=current_user)


@app.route('/settings/profile', methods=['POST'])
@login_required
def update_profile():
    """Update user profile"""
    email = request.form.get('email', '').strip().lower()
    
    if not email or '@' not in email:
        flash('Invalid email address', 'danger')
        return redirect(url_for('settings'))
    
    # Check if email is already taken by another user
    existing_user = User.query.filter_by(email=email).first()
    if existing_user and existing_user.id != current_user.id:
        flash('Email already in use', 'danger')
        return redirect(url_for('settings'))
    
    try:
        current_user.email = email
        db.session.commit()
        
        log_activity('update_profile', details='Updated email')
        flash('Profile updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Profile update error: {str(e)}")
        flash('An error occurred while updating profile', 'danger')
    
    return redirect(url_for('settings'))


@app.route('/settings/password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not current_user.check_password(current_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('settings'))
    
    if len(new_password) < 6:
        flash('New password must be at least 6 characters long', 'danger')
        return redirect(url_for('settings'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('settings'))
    
    try:
        current_user.set_password(new_password)
        db.session.commit()
        
        log_activity('change_password', details='Password changed')
        flash('Password changed successfully', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Password change error: {str(e)}")
        flash('An error occurred while changing password', 'danger')
    
    return redirect(url_for('settings'))


@app.route('/settings/delete-account', methods=['POST'])
@login_required
def delete_account():
    """Delete user account"""
    password = request.form.get('password', '')
    
    if not current_user.check_password(password):
        flash('Incorrect password', 'danger')
        return redirect(url_for('settings'))
    
    try:
        username = current_user.username
        user_id = current_user.id
        
        # Delete user (cascades to bots and activities)
        db.session.delete(current_user)
        db.session.commit()
        
        logout_user()
        
        flash(f'Account {username} has been deleted', 'info')
        return redirect(url_for('index'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Account deletion error: {str(e)}")
        flash('An error occurred while deleting account', 'danger')
        return redirect(url_for('settings'))


# ============================================================================
# ADMIN ROUTES
# ============================================================================

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    total_users = User.query.count()
    total_bots = Bot.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    running_bots = Bot.query.filter_by(status='running').count()
    
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    recent_bots = Bot.query.order_by(Bot.created_at.desc()).limit(10).all()
    recent_activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(20).all()
    
    stats = {
        'total_users': total_users,
        'total_bots': total_bots,
        'active_users': active_users,
        'running_bots': running_bots
    }
    
    return render_template('admin/dashboard.html',
                         stats=stats,
                         recent_users=recent_users,
                         recent_bots=recent_bots,
                         recent_activities=recent_activities)


@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    """Admin user management"""
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)


@app.route('/admin/bots')
@login_required
@admin_required
def admin_bots():
    """Admin bot management"""
    bots = Bot.query.order_by(Bot.created_at.desc()).all()
    return render_template('admin/bots.html', bots=bots)


@app.route('/admin/user/<int:user_id>/toggle-active', methods=['POST'])
@login_required
@admin_required
def admin_toggle_user(user_id):
    """Toggle user active status"""
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('Cannot deactivate your own account', 'danger')
        return redirect(url_for('admin_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User {user.username} has been {status}', 'success')
    
    return redirect(url_for('admin_users'))


@app.route('/admin/user/<int:user_id>/make-admin', methods=['POST'])
@login_required
@admin_required
def admin_make_admin(user_id):
    """Make user an admin"""
    user = User.query.get_or_404(user_id)
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    status = 'granted' if user.is_admin else 'revoked'
    flash(f'Admin privileges {status} for {user.username}', 'success')
    
    return redirect(url_for('admin_users'))


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    """404 error handler"""
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def server_error(e):
    """500 error handler"""
    return render_template('errors/500.html'), 500


@app.errorhandler(403)
def forbidden(e):
    """403 error handler"""
    return render_template('errors/403.html'), 403


# ============================================================================
# CONTEXT PROCESSORS
# ============================================================================

@app.context_processor
def inject_now():
    """Inject current datetime into templates"""
    return {'now': datetime.utcnow()}


@app.context_processor
def inject_app_name():
    """Inject app name into templates"""
    return {'app_name': 'Ladybug'}


# ============================================================================
# CLI COMMANDS
# ============================================================================

@app.cli.command('init-db')
def init_db():
    """Initialize the database"""
    db.create_all()
    print('Database initialized successfully!')


@app.cli.command('create-admin')
def create_admin():
    """Create an admin user"""
    username = input('Enter admin username: ')
    email = input('Enter admin email: ')
    password = input('Enter admin password: ')
    
    if User.query.filter_by(username=username).first():
        print('Username already exists!')
        return
    
    if User.query.filter_by(email=email).first():
        print('Email already exists!')
        return
    
    admin = User(username=username, email=email, is_admin=True)
    admin.set_password(password)
    
    db.session.add(admin)
    db.session.commit()
    
    print(f'Admin user {username} created successfully!')


@app.cli.command('seed-providers')
def seed_providers():
    """Seed hosting providers"""
    providers = [
        {
            'name': 'render',
            'display_name': 'Render',
            'api_endpoint': 'https://api.render.com/v1',
            'description': 'Modern cloud platform with free tier',
            'documentation_url': 'https://render.com/docs'
        },
        {
            'name': 'heroku',
            'display_name': 'Heroku',
            'api_endpoint': 'https://api.heroku.com',
            'description': 'Popular platform-as-a-service',
            'documentation_url': 'https://devcenter.heroku.com'
        },
        {
            'name': 'katabump',
            'display_name': 'Katabump',
            'api_endpoint': 'https://api.katabump.com',
            'description': 'Specialized bot hosting service',
            'documentation_url': 'https://docs.katabump.com'
        }
    ]
    
    for provider_data in providers:
        existing = HostingProvider.query.filter_by(name=provider_data['name']).first()
        if not existing:
            provider = HostingProvider(**provider_data)
            db.session.add(provider)
    
    db.session.commit()
    print('Hosting providers seeded successfully!')


@app.cli.command('cleanup-logs')
def cleanup_logs():
    """Clean up old activity logs (older than 90 days)"""
    cutoff_date = datetime.utcnow() - timedelta(days=90)
    old_logs = ActivityLog.query.filter(ActivityLog.timestamp < cutoff_date).all()
    
    count = len(old_logs)
    for log in old_logs:
        db.session.delete(log)
    
    db.session.commit()
    print(f'Deleted {count} old activity logs')


# ============================================================================
# APPLICATION STARTUP
# ============================================================================

if __name__ == '__main__':
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
        # Seed providers if none exist
        if HostingProvider.query.count() == 0:
            providers = [
                HostingProvider(
                    name='render',
                    display_name='Render',
                    api_endpoint='https://api.render.com/v1',
                    description='Modern cloud platform with free tier',
                    documentation_url='https://render.com/docs'
                ),
                HostingProvider(
                    name='heroku',
                    display_name='Heroku',
                    api_endpoint='https://api.heroku.com',
                    description='Popular platform-as-a-service',
                    documentation_url='https://devcenter.heroku.com'
                ),
                HostingProvider(
                    name='katabump',
                    display_name='Katabump',
                    api_endpoint='https://api.katabump.com',
                    description='Specialized bot hosting service',
                    documentation_url='https://docs.katabump.com'
                )
            ]
            for provider in providers:
                db.session.add(provider)
            db.session.commit()
            print('Hosting providers initialized')
    
    # Get port from environment variable or default to 5000
    port = int(os.environ.get('PORT', 5000))
    
    # Run the application
    app.run(
        host='0.0.0.0',
        port=port,
        debug=os.environ.get('FLASK_ENV') != 'production'
    )
