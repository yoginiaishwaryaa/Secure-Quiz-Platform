from flask import Blueprint, jsonify, render_template, session, request, url_for
from extensions import db, bcrypt, mail
from models import User, Score, Quiz, AuditLog, AccessRequest
from routes.auth import role_required
from crypto_utils import RSASigner, AESCipher
from flask_mail import Message
import json
import random
import string
import os

admin_bp = Blueprint('admin', __name__)
signer = RSASigner()
aes = AESCipher()

@admin_bp.route('/dashboard')
@role_required('admin')
def dashboard():
    # Show only Moderators and Players
    users = User.query.filter(User.role != 'admin').all()
    quizzes = Quiz.query.all()
    # Fetch pending access requests
    pending_requests = AccessRequest.query.filter_by(status='pending').all()
    requests_data = []
    for r in pending_requests:
        u = User.query.get(r.user_id)
        if not u:
            continue
        
        q_title = "Unknown Quiz"
        q_id = None
        
        if r.quiz_id:
            q = Quiz.query.get(r.quiz_id)
            if q:
                q_title = q.title
                q_id = q.id
        else:
            q_title = "Platform Registration"
            
        requests_data.append({'id': r.id, 'username': u.username, 'quiz_title': q_title, 'user_id': u.id, 'quiz_id': q_id})

    # Fetch pending users
    pending_users = User.query.filter_by(is_approved=False).all()

    # XP Summary Stats
    player_users = [u for u in users if u.role == 'player']
    xp_stats = {
        'total': sum(u.total_xp for u in player_users),
        'avg': round(sum(u.total_xp for u in player_users) / len(player_users), 1) if player_users else 0,
        'max': max([u.total_xp for u in player_users]) if player_users else 0
    }

    return render_template('admin_dashboard.html', 
                          users=users, 
                          quizzes=quizzes,
                          pending_requests=requests_data,
                          pending_users=pending_users,
                          xp_stats=xp_stats)

@admin_bp.route('/approve_user/<int:user_id>', methods=['POST'])
@role_required('admin')
def approve_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        # Stage 1: Preliminary Approval (Screening)
        # Instead of full is_approved=True, we create a platform access request
        existing_req = AccessRequest.query.filter_by(user_id=user_id, request_type='platform').first()
        if not existing_req:
            new_req = AccessRequest(user_id=user_id, request_type='platform', status='pending')
            db.session.add(new_req)
            db.session.commit()
        
        return jsonify({'message': f'User {user.username} screened. Proceed to 2FA Verification list.'})
    except Exception as e:
        db.session.rollback()
        print(f"Error approving user: {e}")
        return jsonify({'message': f'Server Error: {str(e)}'}), 500

@admin_bp.route('/delete_user/<int:user_id>', methods=['POST'])
@role_required('admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        return jsonify({'message': 'Cannot delete an Admin.'}), 403
        
    try:
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
        return jsonify({'message': f'User {user.username} (and all their associated data/quizzes) deleted.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error deleting user: {str(e)}'}), 500

@admin_bp.route('/block_user/<int:user_id>', methods=['POST'])
@role_required('admin')
def block_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        return jsonify({'message': 'Cannot block an Admin.'}), 403
        
    user.is_blocked = True
    db.session.commit()
    return jsonify({'message': f'User {user.username} and their email have been blocked.'})

@admin_bp.route('/approve_access/<int:request_id>', methods=['POST'])
@role_required('admin')
def approve_access(request_id):
    req = AccessRequest.query.get_or_404(request_id)
    user = User.query.get(req.user_id)
    
    # Generate 2FA OTP
    otp = ''.join(random.choices(string.digits, k=6))
    otp_hash = bcrypt.generate_password_hash(otp).decode('utf-8')
    
    req.status = 'approved'
    req.otp_hash = otp_hash
    db.session.commit()
    
    # Send OTP to user
    if req.request_type == 'platform':
        subject = "SecureQuiz - Platform Registration 2FA"
        body = f"Hello {user.username},\n\nYour registration has been screened. Use the 2FA code below to finalize your account activation:\n\nCode: {otp}\n\nYou will be asked to enter this on your first login."
    else:
        subject = "Quiz Access: 2FA Verification Code"
        body = f"Hello {user.username},\n\nYour quiz access request has been approved. Verification Code: {otp}"

    msg = Message(subject,
                  sender=os.environ.get('MAIL_USERNAME'),
                  recipients=[user.email])
    msg.body = body
    
    try:
        mail.send(msg)
        return jsonify({'message': f'2FA OTP sent to {user.username}.'})
    except Exception as e:
        return jsonify({'message': f'Approved but email failed: {str(e)}'}), 500

