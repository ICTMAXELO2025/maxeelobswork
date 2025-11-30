
import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import uuid
import bcrypt
from dotenv import load_dotenv
import re

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Railway-specific configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'railway-default-secret-key-change-in-production')

# Database configuration with better error handling
def get_database_url():
    # Try Railway's DATABASE_URL first
    database_url = os.getenv('DATABASE_URL')
    
    if database_url:
        print(f"Found DATABASE_URL: {database_url[:20]}...")  # Log first 20 chars
        # Fix common PostgreSQL URL issues
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
            print("Fixed postgres:// to postgresql://")
        
        return database_url
    else:
        # Fallback for local development
        print("DATABASE_URL not found, using fallback configuration")
        db_user = os.getenv('DB_USER', 'postgres')
        db_password = os.getenv('DB_PASSWORD', 'Maxelo%402023')
        db_host = os.getenv('DB_HOST', 'localhost')
        db_port = os.getenv('DB_PORT', '5432')
        db_name = os.getenv('DB_NAME', 'maxelo')
        
        return f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

# Set database configuration
database_url = get_database_url()
if database_url:
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    print(f"Using database: {database_url.split('@')[-1]}")  # Log database location
else:
    # Fallback to SQLite if no database URL is available
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///local.db'
    print("Using SQLite fallback database")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True
}

app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_FILE_SIZE', 16 * 1024 * 1024))

# Ensure upload directories exist
for folder in ['documents', 'images', 'profiles']:
    os.makedirs(f'{app.config["UPLOAD_FOLDER"]}/{folder}', exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)  # Initialize with app directly
login_manager = LoginManager(app)
login_manager.login_view = 'login'
    
    return app

# Create app instance
app = create_app()

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    surname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    cellphone = db.Column(db.String(15), nullable=False)
    position = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_path = db.Column(db.String(500), nullable=True)
    file_name = db.Column(db.String(300), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    priority = db.Column(db.String(20), nullable=False)
    deadline = db.Column(db.DateTime, nullable=False)
    is_completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class FileFolder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('file_folder.id'), nullable=True)
    is_folder = db.Column(db.Boolean, default=True)
    file_path = db.Column(db.String(500), nullable=True)
    file_type = db.Column(db.String(50), nullable=True)
    file_size = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    role = db.Column(db.String(20), nullable=False)
    user = db.relationship('User', backref='login_logs')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_user_id():
    last_user = User.query.order_by(User.id.desc()).first()
    if last_user and last_user.user_id.startswith('MAXELOBS-'):
        try:
            last_number = int(last_user.user_id.split('-')[1])
            new_number = last_number + 1
        except:
            new_number = 202500
    else:
        new_number = 202500
    return f"MAXELOBS-{new_number}"

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx'
    }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email, is_active=True).first()
        
        if user and user.check_password(password):
            if user.role == 'both':
                session['temp_user_id'] = user.id
                return redirect(url_for('role_selection'))
            elif user.role == 'admin':
                login_user(user)
                log_login(user.id, 'admin')
                return redirect(url_for('admin_dashboard'))
            else:
                login_user(user)
                log_login(user.id, 'employee')
                return redirect(url_for('employee_dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('auth/login.html')

@app.route('/role-selection')
def role_selection():
    user_id = session.get('temp_user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    user = User.query.get(user_id)
    return render_template('auth/role_selection.html', user=user)

@app.route('/select-role/<role>')
def select_role(role):
    user_id = session.get('temp_user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    user = User.query.get(user_id)
    login_user(user)
    log_login(user.id, role)
    session.pop('temp_user_id', None)
    
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('employee_dashboard'))

def log_login(user_id, role):
    login_log = LoginLog(user_id=user_id, role=role)
    db.session.add(login_log)
    db.session.commit()

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        user_id = request.form['user_id']
        email = request.form['email']
        
        user = User.query.filter_by(user_id=user_id, email=email, is_active=True).first()
        if user:
            # Redirect to reset password page with user details
            return redirect(url_for('reset_password', user_id=user_id, email=email))
        else:
            flash('Invalid User ID or Email', 'error')
    
    return render_template('auth/forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        user_id = request.form['user_id']
        email = request.form['email']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Validate passwords match
        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('auth/reset_password.html', 
                                 user_id=user_id, 
                                 email=email)
        
        # Validate password strength
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('auth/reset_password.html', 
                                 user_id=user_id, 
                                 email=email)
        
        # Find user and reset password
        user = User.query.filter_by(user_id=user_id, email=email, is_active=True).first()
        if user:
            user.set_password(new_password)
            db.session.commit()
            flash('Password reset successfully! You can now login with your new password.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid User ID or Email', 'error')
            return redirect(url_for('forgot_password'))
    
    # GET request - check if user came from forgot password
    user_id = request.args.get('user_id')
    email = request.args.get('email')
    
    if not user_id or not email:
        flash('Please use the forgot password form first', 'error')
        return redirect(url_for('forgot_password'))
    
    return render_template('auth/reset_password.html', 
                         user_id=user_id, 
                         email=email)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Admin Routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role not in ['admin', 'both']:
        flash('Access denied', 'error')
        return redirect(url_for('employee_dashboard'))
    
    total_employees = User.query.filter_by(is_active=True).count()
    total_messages = Message.query.filter_by(receiver_id=current_user.id).count()
    unread_messages = Message.query.filter_by(receiver_id=current_user.id, is_read=False).count()
    
    return render_template('admin/admin_dashboard.html',
                         total_employees=total_employees,
                         total_messages=total_messages,
                         unread_messages=unread_messages)

@app.route('/admin/manage-employees', methods=['GET', 'POST'])
@login_required
def manage_employees():
    if current_user.role not in ['admin', 'both']:
        flash('Access denied', 'error')
        return redirect(url_for('employee_dashboard'))
    
    if request.method == 'POST':
        name = request.form['name']
        surname = request.form['surname']
        email = request.form['email']
        cellphone = request.form['cellphone']  # New field
        position = request.form['position']
        role = request.form['role']
        password = request.form['password']
        
        user_id = generate_user_id()
        new_user = User(
            user_id=user_id,
            name=name,
            surname=surname,
            email=email,
            cellphone=cellphone,  # New field
            position=position,
            role=role
        )
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Employee added successfully', 'success')
        except:
            db.session.rollback()
            flash('Error adding employee', 'error')
    
    employees = User.query.filter_by(is_active=True).all()
    return render_template('admin/manage_employees.html', employees=employees)

@app.route('/admin/delete-employee/<int:user_id>')
@login_required
def delete_employee(user_id):
    if current_user.role not in ['admin', 'both']:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    employee = User.query.get(user_id)
    if employee:
        employee.is_active = False
        db.session.commit()
        flash('Employee deleted successfully', 'success')
    else:
        flash('Employee not found', 'error')
    
    return redirect(url_for('manage_employees'))

@app.route('/admin/send-notification', methods=['GET', 'POST'])
@login_required
def send_notification():
    if current_user.role not in ['admin', 'both']:
        flash('Access denied', 'error')
        return redirect(url_for('employee_dashboard'))
    
    if request.method == 'POST':
        title = request.form['title']
        message = request.form['message']
        
        notification = Notification(
            title=title,
            message=message,
            sender_id=current_user.id
        )
        db.session.add(notification)
        db.session.commit()
        flash('Notification sent to all employees', 'success')
    
    return render_template('admin/send_notifications.html')

@app.route('/admin/messages', methods=['GET', 'POST'])
@login_required
def admin_messages():
    if current_user.role not in ['admin', 'both']:
        flash('Access denied', 'error')
        return redirect(url_for('employee_dashboard'))
    
    employees = User.query.filter(User.id != current_user.id, User.is_active == True).all()
    
    if request.method == 'POST':
        receiver_id = request.form['receiver_id']
        subject = request.form['subject']
        message_text = request.form['message']
        file = request.files.get('file')
        
        file_path = None
        file_name = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = f"uploads/documents/{uuid.uuid4()}_{filename}"
            file.save(file_path)
            file_name = filename
        
        new_message = Message(
            subject=subject,
            message=message_text,
            sender_id=current_user.id,
            receiver_id=receiver_id,
            file_path=file_path,
            file_name=file_name
        )
        db.session.add(new_message)
        db.session.commit()
        flash('Message sent successfully', 'success')
    
    sent_messages = Message.query.filter_by(sender_id=current_user.id).order_by(Message.created_at.desc()).all()
    return render_template('admin/messages.html', employees=employees, sent_messages=sent_messages)

@app.route('/admin/search-employees')
@login_required
def search_employees():
    if current_user.role not in ['admin', 'both']:
        return jsonify([])
    
    query = request.args.get('q', '').lower()
    employees = User.query.filter(
        User.is_active == True,
        db.or_(
            User.name.ilike(f'%{query}%'),
            User.surname.ilike(f'%{query}%'),
            User.email.ilike(f'%{query}%'),
            User.user_id.ilike(f'%{query}%'),
            User.cellphone.ilike(f'%{query}%')  # Add cellphone to search
        )
    ).all()
    
    results = []
    for emp in employees:
        results.append({
            'id': emp.id,
            'name': f"{emp.name} {emp.surname}",
            'email': emp.email,
            'cellphone': emp.cellphone,  # Add cellphone to results
            'user_id': emp.user_id,
            'position': emp.position
        })
    
    return jsonify(results)

@app.route('/admin/file-manager', methods=['GET', 'POST'])
@login_required
def admin_file_manager():
    if current_user.role not in ['admin', 'both']:
        flash('Access denied', 'error')
        return redirect(url_for('employee_dashboard'))
    
    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = f"uploads/documents/{uuid.uuid4()}_{filename}"
                file.save(file_path)
                
                new_file = FileFolder(
                    name=filename,
                    user_id=current_user.id,
                    is_folder=False,
                    file_path=file_path,
                    file_type=filename.rsplit('.', 1)[1].lower(),
                    file_size=os.path.getsize(file_path)
                )
                db.session.add(new_file)
                db.session.commit()
                flash('File uploaded successfully', 'success')
        
        elif 'folder_name' in request.form:
            folder_name = request.form['folder_name']
            new_folder = FileFolder(
                name=folder_name,
                user_id=current_user.id,
                is_folder=True
            )
            db.session.add(new_folder)
            db.session.commit()
            flash('Folder created successfully', 'success')
    
    files = FileFolder.query.filter_by(user_id=current_user.id).order_by(FileFolder.created_at.desc()).all()
    return render_template('admin/file_manager.html', files=files)

@app.route('/admin/inbox')
@login_required
def admin_inbox():
    if current_user.role not in ['admin', 'both']:
        flash('Access denied', 'error')
        return redirect(url_for('employee_dashboard'))
    
    received_messages = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.created_at.desc()).all()
    employees = User.query.filter_by(is_active=True).all()
    
    return render_template('admin/inbox.html', messages=received_messages, employees=employees)

@app.route('/api/mark-message-read/<int:message_id>')
@login_required
def api_mark_message_read(message_id):
    """API endpoint to mark message as read (for AJAX calls)"""
    message = Message.query.get(message_id)
    if message and message.receiver_id == current_user.id:
        message.is_read = True
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False})

@app.route('/admin/mark-message-read/<int:message_id>')
@login_required
def admin_mark_message_read(message_id):
    """Admin endpoint to mark message as read (for button clicks)"""
    message = Message.query.get(message_id)
    if message and message.receiver_id == current_user.id:
        message.is_read = True
        db.session.commit()
        flash('Message marked as read', 'success')
    return redirect(url_for('admin_inbox'))

@app.route('/reply-message', methods=['GET', 'POST'])
@login_required
def reply_message():
    if request.method == 'POST':
        reply_to_message_id = request.form.get('reply_to_message_id')
        reply_to_sender_id = request.form.get('reply_to_sender_id')
        subject = request.form.get('subject')
        message_text = request.form.get('message')
        file = request.files.get('file')
        
        # Validate required fields
        if not all([reply_to_message_id, reply_to_sender_id, subject, message_text]):
            flash('All fields are required', 'error')
            return redirect(request.referrer or url_for('employee_inbox'))
        
        # Get the original message to verify permissions
        original_message = Message.query.get(reply_to_message_id)
        if not original_message or original_message.receiver_id != current_user.id:
            flash('Invalid message or permission denied', 'error')
            return redirect(request.referrer or url_for('employee_inbox'))
        
        # Handle file upload
        file_path = None
        file_name = None
        if file and file.filename:
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = f"uploads/documents/{uuid.uuid4()}_{filename}"
                file.save(file_path)
                file_name = filename
            else:
                flash('File type not allowed', 'error')
                return redirect(request.referrer or url_for('employee_inbox'))
        
        # Create reply message
        reply_message = Message(
            subject=subject,
            message=message_text,
            sender_id=current_user.id,
            receiver_id=reply_to_sender_id,
            file_path=file_path,
            file_name=file_name
        )
        
        try:
            db.session.add(reply_message)
            db.session.commit()
            flash('Reply sent successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            print(f"Error sending reply: {e}")
            flash('Error sending reply', 'error')
        
        # Redirect back to the appropriate inbox based on user role
        if current_user.role in ['admin', 'both']:
            return redirect(url_for('admin_inbox'))
        else:
            return redirect(url_for('employee_inbox'))
    
    # If GET request, redirect to inbox
    if current_user.role in ['admin', 'both']:
        return redirect(url_for('admin_inbox'))
    else:
        return redirect(url_for('employee_inbox'))

# Add employee specific mark message read
@app.route('/employee/mark-message-read/<int:message_id>')
@login_required
def employee_mark_message_read(message_id):
    """Employee endpoint to mark message as read (for button clicks)"""
    message = Message.query.get(message_id)
    if message and message.receiver_id == current_user.id:
        message.is_read = True
        db.session.commit()
        flash('Message marked as read', 'success')
    return redirect(url_for('employee_inbox'))

@app.route('/admin/todo', methods=['GET', 'POST'])
@login_required
def admin_todo():
    if current_user.role not in ['admin', 'both']:
        flash('Access denied', 'error')
        return redirect(url_for('employee_dashboard'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        priority = request.form['priority']
        deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')
        
        todo = Todo(
            title=title,
            description=description,
            user_id=current_user.id,
            priority=priority,
            deadline=deadline
        )
        db.session.add(todo)
        db.session.commit()
        flash('Todo added successfully', 'success')
    
    todos = Todo.query.filter_by(user_id=current_user.id).order_by(Todo.deadline.asc()).all()
    return render_template('admin/todo.html', todos=todos)

@app.route('/admin/todo/update/<int:todo_id>', methods=['POST'])
@login_required
def update_todo(todo_id):
    todo = Todo.query.get(todo_id)
    if todo and todo.user_id == current_user.id:
        if 'complete' in request.form:
            todo.is_completed = not todo.is_completed
        elif 'delete' in request.form:
            db.session.delete(todo)
        else:
            todo.title = request.form['title']
            todo.description = request.form['description']
            todo.priority = request.form['priority']
            todo.deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')
        
        db.session.commit()
        flash('Todo updated successfully', 'success')
    
    return redirect(url_for('admin_todo'))

@app.route('/admin/login-logs')
@login_required
def admin_login_logs():
    if current_user.role not in ['admin', 'both']:
        flash('Access denied', 'error')
        return redirect(url_for('employee_dashboard'))
    
    logs = LoginLog.query.order_by(LoginLog.login_time.desc()).limit(50).all()
    return render_template('admin/login_logs.html', logs=logs)

# Employee Routes
@app.route('/employee/dashboard')
@login_required
def employee_dashboard():
    total_todos = Todo.query.filter_by(user_id=current_user.id).count()
    completed_todos = Todo.query.filter_by(user_id=current_user.id, is_completed=True).count()
    unread_messages = Message.query.filter_by(receiver_id=current_user.id, is_read=False).count()
    
    # Get notifications data
    notifications = Notification.query.order_by(Notification.created_at.desc()).limit(10).all()
    recent_notifications = Notification.query.order_by(Notification.created_at.desc()).limit(3).all()
    
    # For demo purposes, we'll show all notifications as unread
    # In a real app, you'd track which notifications each user has read
    unread_notifications = len(notifications)
    
    return render_template('employee/employee_dashboard.html',
                         total_todos=total_todos,
                         completed_todos=completed_todos,
                         unread_messages=unread_messages,
                         unread_notifications=unread_notifications,
                         notifications=notifications,
                         recent_notifications=recent_notifications)

@app.route('/employee/messages', methods=['GET', 'POST'])
@login_required
def employee_messages():
    employees = User.query.filter(User.id != current_user.id, User.is_active == True).all()
    
    if request.method == 'POST':
        receiver_id = request.form['receiver_id']
        subject = request.form['subject']
        message_text = request.form['message']
        file = request.files.get('file')
        
        file_path = None
        file_name = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = f"uploads/documents/{uuid.uuid4()}_{filename}"
            file.save(file_path)
            file_name = filename
        
        new_message = Message(
            subject=subject,
            message=message_text,
            sender_id=current_user.id,
            receiver_id=receiver_id,
            file_path=file_path,
            file_name=file_name
        )
        db.session.add(new_message)
        db.session.commit()
        flash('Message sent successfully', 'success')
    
    sent_messages = Message.query.filter_by(sender_id=current_user.id).order_by(Message.created_at.desc()).all()
    return render_template('employee/messages.html', employees=employees, sent_messages=sent_messages)

@app.route('/employee/search-employees')
@login_required
def employee_search_employees():
    query = request.args.get('q', '').lower()
    employees = User.query.filter(
        User.is_active == True,
        User.id != current_user.id,
        db.or_(
            User.name.ilike(f'%{query}%'),
            User.surname.ilike(f'%{query}%'),
            User.email.ilike(f'%{query}%'),
            User.user_id.ilike(f'%{query}%'),
            User.cellphone.ilike(f'%{query}%')  # Add cellphone to search
        )
    ).all()
    
    results = []
    for emp in employees:
        results.append({
            'id': emp.id,
            'name': f"{emp.name} {emp.surname}",
            'email': emp.email,
            'cellphone': emp.cellphone,  # Add cellphone to results
            'user_id': emp.user_id,
            'position': emp.position
        })
    
    return jsonify(results)

@app.route('/employee/file-manager', methods=['GET', 'POST'])
@login_required
def employee_file_manager():
    folder_id = request.args.get('folder_id', type=int)
    current_folder = None
    folder_path = []
    
    if folder_id:
        current_folder = FileFolder.query.filter_by(id=folder_id, user_id=current_user.id, is_folder=True).first()
        if current_folder:
            # Build folder path
            folder = current_folder
            while folder:
                folder_path.insert(0, folder)
                if folder.parent_id:
                    folder = FileFolder.query.get(folder.parent_id)
                else:
                    folder = None
    
    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = f"uploads/documents/{uuid.uuid4()}_{filename}"
                file.save(file_path)
                
                parent_folder_id = request.form.get('parent_folder_id')
                if parent_folder_id:
                    parent_folder = FileFolder.query.filter_by(id=parent_folder_id, user_id=current_user.id).first()
                    if not parent_folder:
                        flash('Invalid folder selected', 'error')
                        return redirect(url_for('employee_file_manager'))
                
                new_file = FileFolder(
                    name=filename,
                    user_id=current_user.id,
                    is_folder=False,
                    file_path=file_path,
                    file_type=filename.rsplit('.', 1)[1].lower(),
                    file_size=os.path.getsize(file_path),
                    parent_id=parent_folder_id if parent_folder_id else None
                )
                db.session.add(new_file)
                db.session.commit()
                flash('File uploaded successfully', 'success')
        
        elif 'folder_name' in request.form:
            folder_name = request.form['folder_name']
            parent_folder_id = request.form.get('parent_folder_id')
            
            if parent_folder_id:
                parent_folder = FileFolder.query.filter_by(id=parent_folder_id, user_id=current_user.id).first()
                if not parent_folder:
                    flash('Invalid parent folder', 'error')
                    return redirect(url_for('employee_file_manager'))
            
            new_folder = FileFolder(
                name=folder_name,
                user_id=current_user.id,
                is_folder=True,
                parent_id=parent_folder_id if parent_folder_id else None
            )
            db.session.add(new_folder)
            db.session.commit()
            flash('Folder created successfully', 'success')
    
    # Get files and folders for current location
    if current_folder:
        files = FileFolder.query.filter_by(parent_id=current_folder.id, user_id=current_user.id).order_by(FileFolder.is_folder.desc(), FileFolder.name).all()
    else:
        files = FileFolder.query.filter_by(parent_id=None, user_id=current_user.id).order_by(FileFolder.is_folder.desc(), FileFolder.name).all()
    
    # Get all folders for dropdowns
    all_folders = FileFolder.query.filter_by(user_id=current_user.id, is_folder=True).all()
    
    return render_template('employee/file_manager.html', 
                         files=files, 
                         current_folder=current_folder,
                         folder_path=folder_path,
                         all_folders=all_folders)

@app.route('/delete-file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file_item = FileFolder.query.get(file_id)
    if file_item and file_item.user_id == current_user.id and not file_item.is_folder:
        try:
            # Delete physical file
            if os.path.exists(file_item.file_path):
                os.remove(file_item.file_path)
            
            # Delete database record
            db.session.delete(file_item)
            db.session.commit()
            return jsonify({'success': True, 'message': 'File deleted successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})
    
    return jsonify({'success': False, 'message': 'File not found or access denied'})

@app.route('/delete-folder/<int:folder_id>', methods=['POST'])
@login_required
def delete_folder(folder_id):
    folder = FileFolder.query.get(folder_id)
    if folder and folder.user_id == current_user.id and folder.is_folder:
        try:
            # Recursively delete folder contents
            def delete_folder_contents(folder_id):
                contents = FileFolder.query.filter_by(parent_id=folder_id, user_id=current_user.id).all()
                for item in contents:
                    if item.is_folder:
                        delete_folder_contents(item.id)
                    else:
                        # Delete physical file
                        if os.path.exists(item.file_path):
                            os.remove(item.file_path)
                        db.session.delete(item)
                # Delete the folder itself
                folder_to_delete = FileFolder.query.get(folder_id)
                if folder_to_delete:
                    db.session.delete(folder_to_delete)
            
            delete_folder_contents(folder_id)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Folder deleted successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})
    
    return jsonify({'success': False, 'message': 'Folder not found or access denied'})

@app.route('/employee/inbox')
@login_required
def employee_inbox():
    # Get received messages
    received_messages = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.created_at.desc()).all()
    
    # Get all employees to display sender information
    employees = User.query.all()  # Fixed typo
    
    # Create a dictionary for easy employee lookup
    employee_dict = {emp.id: emp for emp in employees}
    
    return render_template('employee/inbox.html', 
                         messages=received_messages, 
                         employees=employee_dict,
                         current_user=current_user)

@app.route('/employee/todo', methods=['GET', 'POST'])
@login_required
def employee_todo():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        priority = request.form['priority']
        deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')
        
        todo = Todo(
            title=title,
            description=description,
            user_id=current_user.id,
            priority=priority,
            deadline=deadline
        )
        db.session.add(todo)
        db.session.commit()
        flash('Todo added successfully', 'success')
    
    todos = Todo.query.filter_by(user_id=current_user.id).order_by(Todo.deadline.asc()).all()
    return render_template('employee/todo.html', todos=todos)

@app.route('/employee/todo/update/<int:todo_id>', methods=['POST'])
@login_required
def employee_update_todo(todo_id):
    todo = Todo.query.get(todo_id)
    if todo and todo.user_id == current_user.id:
        if 'complete' in request.form:
            todo.is_completed = not todo.is_completed
        elif 'delete' in request.form:
            db.session.delete(todo)
        else:
            todo.title = request.form['title']
            todo.description = request.form['description']
            todo.priority = request.form['priority']
            todo.deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')
        
        db.session.commit()
        flash('Todo updated successfully', 'success')
    
    return redirect(url_for('employee_todo'))

# Common Routes
@app.route('/download-file/<int:file_id>')
@login_required
def download_file(file_id):
    file_item = FileFolder.query.get(file_id)
    if file_item and file_item.user_id == current_user.id and not file_item.is_folder:
        return send_file(file_item.file_path, as_attachment=True, download_name=file_item.name)
    flash('File not found', 'error')
    return redirect(request.referrer)

@app.route('/download-message-file/<int:message_id>')
@login_required
def download_message_file(message_id):
    message = Message.query.get(message_id)
    if message and (message.sender_id == current_user.id or message.receiver_id == current_user.id) and message.file_path:
        return send_file(message.file_path, as_attachment=True, download_name=message.file_name)
    flash('File not found', 'error')
    return redirect(request.referrer)

@app.route('/employee/notifications')
@login_required
def employee_notifications():
    # Get all notifications (admin sends to all employees, so no specific receiver_id)
    notifications = Notification.query.order_by(Notification.created_at.desc()).all()
    return render_template('employee/notifications.html', notifications=notifications)

@app.route('/api/mark-notification-read/<int:notification_id>')
@login_required
def mark_notification_read(notification_id):
    # In a real application, you might want to track which user read which notification
    # For now, we'll just return success since notifications are sent to all employees
    return jsonify({'success': True})

@app.route('/api/check-new-notifications')
@login_required
def check_new_notifications():
    # This is a simplified version - in a real app, you'd track which notifications each user has read
    # For now, we'll just check if there are any recent notifications
    recent_notification = Notification.query.order_by(Notification.created_at.desc()).first()
    if recent_notification:
        # Check if notification is from the last 5 minutes
        time_diff = datetime.utcnow() - recent_notification.created_at
        if time_diff.total_seconds() < 300:  # 5 minutes
            return jsonify({'has_new_notifications': True})
    return jsonify({'has_new_notifications': False})

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Handle profile updates
        current_user.name = request.form['name']
        current_user.surname = request.form['surname']
        current_user.email = request.form['email']
        current_user.cellphone = request.form['cellphone']  # New field
        current_user.position = request.form['position']
        
        try:
            db.session.commit()
            flash('Profile updated successfully', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error updating profile', 'error')
    
    # Get statistics for the profile page
    total_todos = Todo.query.filter_by(user_id=current_user.id).count()
    completed_todos = Todo.query.filter_by(user_id=current_user.id, is_completed=True).count()
    total_files = FileFolder.query.filter_by(user_id=current_user.id, is_folder=False).count()
    total_messages_sent = Message.query.filter_by(sender_id=current_user.id).count()
    
    # Get recent activity
    recent_logins = LoginLog.query.filter_by(user_id=current_user.id).order_by(LoginLog.login_time.desc()).limit(5).all()
    
    recent_messages = Message.query.filter_by(sender_id=current_user.id).order_by(Message.created_at.desc()).limit(3).all()
    
    recent_todos = Todo.query.filter_by(user_id=current_user.id).order_by(Todo.created_at.desc()).limit(2).all()
    
    # Pre-process recent messages to include receiver information
    processed_messages = []
    for message in recent_messages:
        receiver = User.query.get(message.receiver_id)
        processed_messages.append({
            'message': message,
            'receiver_name': f"{receiver.name} {receiver.surname}" if receiver else "Unknown User"
        })
    
    # Admin statistics (only calculate if user is admin)
    admin_stats = {}
    if current_user.role in ['admin', 'both']:
        admin_stats = {
            'total_employees': User.query.filter_by(is_active=True).count(),
            'total_notifications': Notification.query.count(),
            'total_messages': Message.query.count(),
            'active_tasks': Todo.query.filter_by(is_completed=False).count()
        }
    
    return render_template('profile.html', 
                         user=current_user,
                         total_todos=total_todos,
                         completed_todos=completed_todos,
                         total_files=total_files,
                         total_messages_sent=total_messages_sent,
                         recent_logins=recent_logins,
                         processed_messages=processed_messages,
                         recent_todos=recent_todos,
                         admin_stats=admin_stats)





# Initialize database with error handling
def init_db():
    with app.app_context():
        try:
            print("Creating database tables...")
            db.create_all()
            print("Database tables created successfully")
            
            # Create default admin user if not exists
            admin = User.query.filter_by(email='admin@maxelobs.com').first()
            if not admin:
                admin_user = User(
                    user_id='MAXELOBS-202500',
                    name='Katlego',
                    surname='Papala',
                    email='admin@maxelobs.com',
                    cellphone='0123456789',
                    position='System Administrator',
                    role='both'
                )
                admin_user.set_password('Admin@123')
                db.session.add(admin_user)
                db.session.commit()
                print("Default admin user created!")
            else:
                print("Admin user already exists")
                
        except Exception as e:
            print(f"Error initializing database: {e}")
            # Don't raise the exception to allow the app to start

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Get port from environment or default to 5000
    port = int(os.environ.get('PORT', 5000))
    print(f"Starting server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)