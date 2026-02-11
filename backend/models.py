from extensions import db
from datetime import datetime

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # player, moderator, admin
    total_xp = db.Column(db.Integer, default=0)
    is_approved = db.Column(db.Boolean, default=False)
    is_blocked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    scores = db.relationship('Score', backref='player', lazy=True)
    access_requests = db.relationship('AccessRequest', backref='player', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='actor', lazy=True)

class Quiz(db.Model):
    __tablename__ = 'quizzes'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    questions_json = db.Column(db.Text, nullable=False)  # Encrypted JSON blob
    is_active = db.Column(db.Boolean, default=True)
    end_time = db.Column(db.DateTime, nullable=True)
    difficulty_map = db.Column(db.Text, nullable=True) # JSON storing Di for questions
    access_code = db.Column(db.String(6), nullable=True) # 6-digit OTP for quiz access

    scores = db.relationship('Score', backref='quiz', lazy=True)

class Score(db.Model):
    __tablename__ = 'scores_rewards'
    __table_args__ = (db.UniqueConstraint('user_id', 'quiz_id', name='unique_user_quiz_attempt'),)
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=False)
    aes_score = db.Column(db.Text, nullable=False) # Encrypted score (Text for JSON payload)
    max_streak = db.Column(db.Integer, default=0)
    base64_signature = db.Column(db.Text, nullable=True) # RSA Signature of the achievement
    xp_earned = db.Column(db.Integer, default=0)
    attempted_at = db.Column(db.DateTime, default=datetime.utcnow)

class AccessRequest(db.Model):
    __tablename__ = 'access_requests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quizzes.id'), nullable=True) # Null for platform level
    request_type = db.Column(db.String(20), default='quiz') # 'quiz' or 'platform'
    status = db.Column(db.String(20), default='pending')  # pending, approved, verified
    otp_hash = db.Column(db.String(128), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
