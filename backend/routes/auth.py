import random
import string
import os
import re
from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for
from flask_mail import Message
from extensions import db, bcrypt, mail
from models import User
from sqlalchemy.exc import IntegrityError
from functools import wraps
from datetime import datetime, timedelta

auth_bp = Blueprint('auth', __name__)

# --- RBAC Decorators ---
# --- [REQUIREMENT: Authorization - Access Control] ---
# Implementation of Access Control Matrix/RBAC
# Subjects: Admin, Moderator, Player
# Objects: User Accounts, Quizzes, Scores
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                 return jsonify({'error': 'Unauthorized'}), 401
            
            user = User.query.get(session['user_id'])
            if not user or user.role != required_role: # Simple check, can be expanded for hierarchy
                 # Allow Admin to access Mod/Player routes if hierarchy needed? 
                 # Prompt implies strict separation, or at least Admin manages.
                 
                 # Strict check for now
                 if required_role == 'admin' and user.role != 'admin':
                     return jsonify({'error': 'Forbidden: Admin access only'}), 403
                 if required_role == 'moderator' and user.role != 'moderator':
                     return jsonify({'error': 'Forbidden: Moderator access only'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Routes ---

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
        
    data = request.get_json(silent=True) or request.form
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'player') # Default to player
    
    if not username or not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400

    username = username.strip()
    email = email.strip()
    
    # SECURITY: Prevent Admin Self-Registration
    if role.lower() == 'admin':
        return jsonify({'message': 'Admin registration is restricted. Contact System Administrator.'}), 403

    import re
    if len(password) < 8:
        return jsonify({'message': 'Password must be at least 8 characters long'}), 400
    if not re.search(r'[A-Z]', password) or not re.search(r'\d', password):
        return jsonify({'message': 'Password must contain at least 1 uppercase letter and 1 number'}), 400

    existing_username = User.query.filter(db.func.lower(User.username) == username.lower()).first()
    if existing_username:
        return jsonify({'field': 'username', 'message': 'This username is already taken. Please choose another.'}), 409
        
    existing_email = User.query.filter(db.func.lower(User.email) == email.lower()).first()
    if existing_email:
        if existing_email.is_blocked:
            return jsonify({'message': 'This email address has been blocked from the system.'}), 403
        return jsonify({'field': 'email', 'message': 'This email is already registered. Try logging in.'}), 409

    try:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        # --- [REQUIREMENT: Hashing with Salt] ---
        # Implementation: Secure storage of passwords using bcrypt (auto-salting)
        # Admin is auto-approved, others need verification
        is_approved = (role.lower() == 'admin')
        new_user = User(username=username, email=email, password_hash=hashed_password, role=role, is_approved=is_approved)
        
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError as e:
        db.session.rollback()
        print(f"IntegrityError during Registration: {e}")
        # Detect specific duplicate key
        err_msg = str(e)
        if "Duplicate entry" in err_msg:
            if "users.username" in err_msg or "key 'username'" in err_msg:
                return jsonify({'field': 'username', 'message': 'This username is already taken. Please choose another.'}), 409
            if "users.email" in err_msg or "key 'email'" in err_msg:
                return jsonify({'field': 'email', 'message': 'This email is already registered. Try logging in.'}), 409
        
        return jsonify({'message': 'An error occurred during registration (Integrity Error). Please try again.'}), 500
    except Exception as e:
        db.session.rollback()
        print(f"Registration Error: {e}")
        return jsonify({'message': 'An error occurred during registration. Please try again.'}), 500

    approval_msg = "User registered successfully. Admin approval required before login." if not is_approved else "Admin account registered successfully."
    return jsonify({'message': approval_msg}), 201

# --- [REQUIREMENT: Single-Factor Authentication (SFA)] ---
# Mechanism: Password/Username based login flow
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    data = request.get_json(silent=True) or request.form
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    
    if user and bcrypt.check_password_hash(user.password_hash, password):
        # SECURITY: Check for Blocks
        if user.is_blocked:
            return jsonify({'message': 'Your account has been blocked by the Administrator.'}), 403

        platform_req = None
        # SECURITY: Check for Admin Approval
        if not user.is_approved:
            # Check if they are in Stage 2 (Pending 2FA Activation)
            from models import AccessRequest
            platform_req = AccessRequest.query.filter_by(user_id=user.id, request_type='platform', status='approved').first()
            if not platform_req:
                return jsonify({'message': 'Your account is pending Admin approval. Please try again later.'}), 403
            
        # If in Stage 2, we skip generating a NEW otp and skip sending email
        # The user should use the one already sent by Admin.
        if platform_req:
            session['temp_user_id'] = user.id
            return jsonify({
                'message': 'Please enter the Activation Code sent to your email after Admin screening.',
                'redirect': url_for('auth.verify_otp')
            })

        # Standard Login Flow
        # Generate OTP
        otp = ''.join(random.choices(string.digits, k=6))
        
        # Send via Email using Flask-Mail
        try:
            msg = Message("Your SecureQuiz Login OTP", 
                          sender=os.environ.get('MAIL_USERNAME'),
                          recipients=[user.email])
            msg.body = f"Your OTP is: {otp}\n\nThis code expires in 5 minutes."
            mail.send(msg)
            print(f"DEBUG: Email sent to {user.email}")
        except Exception as e:
            print(f"Error sending email: {e}")
            print(f"------------ OTP for {user.email} (Fallback): {otp} ------------")

        # Store OTP in session (secure server-side storage)
        # --- [REQUIREMENT: Multi-Factor Authentication (MFA)] ---
        # Implementation: Password + Email OTP code
        session['temp_user_id'] = user.id
        session['otp'] = otp
        session['otp_expiry'] = (datetime.utcnow() + timedelta(seconds=300)).isoformat()
        
        if request.is_json:
             return jsonify({'message': 'OTP sent', 'redirect': url_for('auth.verify_otp')})
        else:
             return redirect(url_for('auth.verify_otp'))

    return jsonify({'message': 'Invalid credentials'}), 401

@auth_bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'GET':
        return render_template('otp.html')

    data = request.get_json(silent=True) or request.form
    user_otp = data.get('otp')
    if user_otp:
        user_otp = user_otp.strip()
    
    stored_otp = session.get('otp')
    expiry_str = session.get('otp_expiry')
    temp_user_id = session.get('temp_user_id')
    
    if not temp_user_id:
        return jsonify({'message': 'Session expired or invalid'}), 401

    user = User.query.get(temp_user_id)
    from models import AccessRequest
    platform_req = AccessRequest.query.filter_by(user_id=user.id, request_type='platform', status='approved').first()

    # --- Verification Logic ---
    is_valid = False
    if platform_req:
        # Check against Admin-sent Activation OTP
        if user_otp and bcrypt.check_password_hash(platform_req.otp_hash, user_otp):
            is_valid = True
            user.is_approved = True  # ACTIVATE ACCOUNT
            db.session.delete(platform_req)
            db.session.commit()
    elif stored_otp and user_otp == stored_otp:
        # Standard Login OTP check
        if datetime.utcnow() <= datetime.fromisoformat(expiry_str):
            is_valid = True

    if is_valid:
        # Success
        session['user_id'] = temp_user_id
        session.pop('otp', None)
        session.pop('otp_expiry', None)
        
        session['role'] = user.role # Store role for Jinja templates
        session['username'] = user.username
        
        target_dashboard = {
            'player': 'quiz.player_dashboard',
            'moderator': 'quiz.moderator_dashboard',
            'admin': 'admin.dashboard'
        }
        
        if request.is_json:
             return jsonify({'message': 'Login successful', 'redirect': url_for(target_dashboard.get(user.role, 'index'))})
        else:
             return redirect(url_for(target_dashboard.get(user.role, 'index')))
    
    return jsonify({'message': 'Invalid OTP'}), 401

@auth_bp.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
        
    try:
        from models import Score, AccessRequest, AuditLog, Quiz
        # 1. Delete data specifically tied to this USER (where they are the player/attendee)
        Score.query.filter_by(user_id=user_id).delete()
        AccessRequest.query.filter_by(user_id=user_id).delete()
        AuditLog.query.filter_by(user_id=user_id).delete()
        
        # 2. If Moderator, cascade delete QUIZZES they created
        if user.role == 'moderator':
            created_quizzes = Quiz.query.filter_by(created_by=user_id).all()
            for quiz in created_quizzes:
                # Delete scores/requests for these quizzes (belonging to OTHER players)
                Score.query.filter_by(quiz_id=quiz.id).delete()
                AccessRequest.query.filter_by(quiz_id=quiz.id).delete()
                db.session.delete(quiz)
        
        db.session.delete(user)
        db.session.commit()
        session.clear()
        return jsonify({'message': 'Account deleted successfully', 'redirect': url_for('index')})
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error deleting account: {str(e)}'}), 500

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))
