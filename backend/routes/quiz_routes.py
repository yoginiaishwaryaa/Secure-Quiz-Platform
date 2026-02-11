from flask import Blueprint, render_template, request, session, jsonify, redirect, url_for
from extensions import db, mail
from flask_mail import Message
from models import Quiz, Score, User, AuditLog, AccessRequest
from routes.auth import role_required, login_required
from crypto_utils import AESCipher
import json
import random
import string
import qrcode
import io
import base64
import os
from datetime import datetime

quiz_bp = Blueprint('quiz', __name__)
aes = AESCipher()

@quiz_bp.route('/summary/<int:quiz_id>')
@login_required
def quiz_summary(quiz_id):
    # Allow Moderator (Creator) OR Admin
    quiz = Quiz.query.get_or_404(quiz_id)
    user = User.query.get(session['user_id'])
    
    if user.role != 'admin' and (user.role != 'moderator' or quiz.created_by != user.id):
        return jsonify({'error': 'Unauthorized'}), 403
        
    scores = Score.query.filter_by(quiz_id=quiz_id).all()
    
    summary_data = []
    for s in scores:
        player = User.query.get(s.user_id)
        # Decrypt raw score to get correct count
        try:
            raw = aes.decrypt(s.aes_score)
            if isinstance(raw, str): raw = json.loads(raw)
            correct = raw.get('correct_count', 0)
        except:
            correct = '?'
            
        summary_data.append({
            'score_id': s.id,
            'username': player.username,
            'xp': s.xp_earned,
            'correct_count': correct,
            'timestamp': s.attempted_at.strftime('%Y-%m-%d %H:%M')
        })
        
    return render_template('quiz_summary.html', quiz=quiz, summary=summary_data)

@quiz_bp.route('/moderator/attempt/<int:score_id>')
@login_required
def attempt_details(score_id):
    score = Score.query.get_or_404(score_id)
    quiz = Quiz.query.get(score.quiz_id)
    user_viewer = User.query.get(session['user_id'])
    
    # Check ownership (Creator or Admin)
    if user_viewer.role != 'admin' and (user_viewer.role != 'moderator' or quiz.created_by != user_viewer.id):
        return jsonify({'error': 'Unauthorized'}), 403
        
    user_player = User.query.get(score.user_id)
    
    # Decrypt everything
    try:
        score_data = aes.decrypt(score.aes_score)
        if isinstance(score_data, str): score_data = json.loads(score_data)
        
        q_data = aes.decrypt(quiz.questions_json)
        if isinstance(q_data, str): q_data = json.loads(q_data)
    except:
        return "Decryption Error", 500
        
    user_answers = score_data.get('user_answers', {})
    
    # Reconstruct Layout
    details = []
    for q in q_data:
        qid = str(q['id'])
        user_choice_idx = int(user_answers.get(qid, -1)) if qid in user_answers else -1
        
        is_correct = (user_choice_idx == int(q['correct_option']))
        
        details.append({
            'text': q['text'],
            'options': q['options'],
            'correct_option': q['correct_option'],
            'user_choice': user_choice_idx,
            'is_correct': is_correct,
            'difficulty': q['difficulty']
        })
        
    return render_template('attempt_details.html', quiz=quiz, user=user_player, details=details, score=score, viewer=user_viewer, score_data=score_data)

@quiz_bp.route('/dashboard')
@login_required
def player_dashboard():
    # Show available quizzes
    active_quizzes = Quiz.query.filter_by(is_active=True).all()
    user_id = session['user_id']
    attempted_ids = [s.quiz_id for s in Score.query.filter_by(user_id=user_id).all()]
    
    # Fetch access request statuses
    requests = AccessRequest.query.filter_by(user_id=user_id).all()
    request_map = {r.quiz_id: r.status for r in requests}
    
    return render_template('player_dashboard.html', 
                          quizzes=active_quizzes, 
                          attempted_ids=attempted_ids, 
                          request_map=request_map,
                          user=User.query.get(user_id))

@quiz_bp.route('/history')
@login_required
def history():
    user_id = session['user_id']
    attempts = Score.query.filter_by(user_id=user_id).all()
    
    history_data = []
    for score in attempts:
        quiz = Quiz.query.get(score.quiz_id)
        
        # Decrypt Score for display
        try:
            decrypted_score = aes.decrypt(score.aes_score)
            if isinstance(decrypted_score, str):
                 decrypted_score = json.loads(decrypted_score)
            
            # Count total questions for context
            q_data = aes.decrypt(quiz.questions_json)
            if isinstance(q_data, str):
                q_data = json.loads(q_data)
            total_q = len(q_data) if q_data else 0
            
            raw_score = f"{decrypted_score.get('correct_count', 0)} / {total_q}"
        except:
            raw_score = "Encrypted"
            
        item = {
            'quiz_title': quiz.title,
            'xp_earned': score.xp_earned,
            'signature': score.base64_signature,
            'timestamp': score.attempted_at,
            'quiz_active': quiz.is_active,
            'answers': None,
            'raw_score': raw_score
        }
        
        # If Quiz is closed, reveal answers
        if not quiz.is_active:
             # Decrypt Quiz Questions to show answers
             decrypted_questions = aes.decrypt(quiz.questions_json)
             if isinstance(decrypted_questions, str):
                 decrypted_questions = json.loads(decrypted_questions)
             item['answers'] = decrypted_questions
             
        history_data.append(item)
        
    return render_template('history.html', history=history_data)

@quiz_bp.route('/moderator/dashboard')
@role_required('moderator')
def moderator_dashboard():
    quizzes = Quiz.query.filter_by(created_by=session['user_id']).all()
    return render_template('moderator_dashboard.html', quizzes=quizzes)

@quiz_bp.route('/request_create_otp', methods=['POST'])
@role_required('moderator')
def request_create_otp():
    user = User.query.get(session['user_id'])
    otp = ''.join(random.choices(string.digits, k=6))
    session['create_otp'] = otp
    
    try:
        msg = Message("SecureQuiz - Create Quiz 2FA",
                      sender=os.environ.get('MAIL_USERNAME'),
                      recipients=[user.email])
        msg.body = f"Hello Moderator {user.username},\n\nUse the code below to authorize the creation of your new quiz:\n\nCode: {otp}"
        mail.send(msg)
        return jsonify({'message': 'OTP sent to your email.'})
    except Exception as e:
        return jsonify({'message': f'Error sending OTP: {str(e)}'}), 500

@quiz_bp.route('/create', methods=['POST'])
@role_required('moderator')
def create_quiz():
    data = request.json
    otp = data.get('otp')
    
    if not otp or otp != session.get('create_otp'):
        return jsonify({'message': 'Invalid or missing 2FA code.'}), 400
    
    session.pop('create_otp', None) # Burn the OTP
    
    title = data.get('title')
    questions = data.get('questions') # List of dicts: {id, text, options, correct_option, difficulty}
    
    # 1. Extract Difficulty Map
    difficulty_map = {q['id']: int(q['difficulty']) for q in questions}
    
    # 2. Encrypt Questions JSON
    questions_json = json.dumps(questions)
    # --- [REQUIREMENT: Encryption & Decryption] ---
    # Implementation: Questions are AES encrypted before being stored
    encrypted_questions = aes.encrypt(questions_json)
    
    # 3. Generate Access Code
    access_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    
    new_quiz = Quiz(
        title=title,
        created_by=session['user_id'],
        questions_json=encrypted_questions,
        difficulty_map=json.dumps(difficulty_map),
        is_active=True,
        access_code=access_code
    )
    
    db.session.add(new_quiz)
    db.session.commit()
    
    return jsonify({'message': 'Quiz created successfully', 'quiz_id': new_quiz.id, 'access_code': access_code})

@quiz_bp.route('/qr/<int:quiz_id>')
@login_required
def get_quiz_qr(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    # Data to encode in QR (e.g., just the Access Code, or a direct link if we buy a domain)
    # For now, let's encode the Access Code mostly
    qr_data = f"ACCESS_CODE:{quiz.access_code}"
    
    # --- [REQUIREMENT: Encoding - QR Code] ---
    # Implementation: Dynamic generation of Barcode/QR Code for access
    img = qrcode.make(qr_data)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    img_b64 = base64.b64encode(buf.getvalue()).decode()
    
    return jsonify({'qr_image': img_b64, 'access_code': quiz.access_code})

@quiz_bp.route('/request_access/<int:quiz_id>', methods=['POST'])
@login_required
def request_access(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    user_id = session['user_id']
    user = User.query.get(user_id)
    
    # Check if already attempted
    if Score.query.filter_by(user_id=user_id, quiz_id=quiz_id).first():
        return jsonify({'message': 'You have already attempted this quiz'}), 400
        
    # Check if a verified/approved request already exists
    existing = AccessRequest.query.filter_by(user_id=user_id, quiz_id=quiz_id).first()
    if existing and existing.status in ['approved', 'verified']:
        return jsonify({'message': f'You already have an {existing.status} request. Please check your email/dashboard.'})
    
    # Automatic approval as per user request
    from extensions import bcrypt, mail
    otp = ''.join(random.choices(string.digits, k=6))
    otp_hash = bcrypt.generate_password_hash(otp).decode('utf-8')
    
    if existing:
        existing.status = 'approved'
        existing.otp_hash = otp_hash
    else:
        new_request = AccessRequest(user_id=user_id, quiz_id=quiz_id, status='approved', otp_hash=otp_hash)
        db.session.add(new_request)
    
    db.session.commit()
    
    # Send OTP to user
    try:
        msg = Message(f"Quiz Access: 2FA for '{quiz.title}'",
                      sender=os.environ.get('MAIL_USERNAME'),
                      recipients=[user.email])
        msg.body = f"Hello {user.username},\n\nYour request to attempt '{quiz.title}' has been automatically approved.\n\nVerification Code: {otp}\n\nOnce verified on your dashboard, your access code will be revealed."
        mail.send(msg)
        return jsonify({'message': 'Access approved! A 2FA OTP has been sent to your email.'})
    except Exception as e:
        print(f"Mail Error: {e}")
        return jsonify({'message': 'Access approved but failed to send OTP email.'}), 500

@quiz_bp.route('/verify_otp/<int:quiz_id>', methods=['POST'])
@login_required
def verify_otp(quiz_id):
    data = request.get_json()
    otp = data.get('otp')
    user_id = session['user_id']
    
    req = AccessRequest.query.filter_by(user_id=user_id, quiz_id=quiz_id, status='approved').first()
    if not req:
        return jsonify({'message': 'No approved request found'}), 404
        
    from extensions import bcrypt
    if bcrypt.check_password_hash(req.otp_hash, otp):
        req.status = 'verified'
        db.session.commit()
        quiz = Quiz.query.get(quiz_id)
        return jsonify({'message': 'Verified', 'access_code': quiz.access_code})
    else:
        return jsonify({'message': 'Invalid OTP'}), 400

@quiz_bp.route('/join', methods=['GET'])
@login_required
def join_quiz():
    code = request.args.get('code', '').strip().upper()
    if not code:
        return render_template('player_dashboard.html', error="Please enter a code", quizzes=Quiz.query.filter_by(is_active=True).all())
        
    # Find active quiz with this code
    quiz = Quiz.query.filter_by(access_code=code, is_active=True).first()
    
    if quiz:
        return redirect(url_for('quiz.attempt_quiz', quiz_id=quiz.id, code=code))
    else:
        # Flash message ideally, or render dashboard with error
        return render_template('player_dashboard.html', error="Invalid or Expired Code", quizzes=Quiz.query.filter_by(is_active=True).all())

@quiz_bp.route('/end/<int:quiz_id>', methods=['POST'])
@role_required('moderator')
def end_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    if quiz.created_by != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
        
    quiz.is_active = False
    quiz.end_time = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'message': 'Quiz ended. Answers revealed to players.'})

@quiz_bp.route('/attempt/<int:quiz_id>', methods=['GET'])
@login_required
def attempt_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    code_input = request.args.get('code')
    
    # Verify Access Code
    # Verify Access Code
    if not code_input or (quiz.access_code and code_input.upper() != quiz.access_code):
        if quiz.access_code:
             return render_template('player_dashboard.html', quizzes=Quiz.query.filter_by(is_active=True).all(), 
                                    attempted_ids=[s.quiz_id for s in Score.query.filter_by(user_id=session['user_id']).all()],
                                    error="Invalid Access Code")
        
    if not quiz.is_active:
        return "Quiz is closed", 403
        
    # Check if already attempted
    if Score.query.filter_by(user_id=session['user_id'], quiz_id=quiz_id).first():
        return redirect(url_for('quiz.history'))
        
    # Decrypt questions to send to frontend (WITHOUT correct answers if possible, but for simplicity we send logic to front or mask it. 
    # SECURE WAY: Backend renders template with questions, strips 'correct_option'.
    
    questions = aes.decrypt(quiz.questions_json)
    if isinstance(questions, str):
        try:
             questions = json.loads(questions)
        except:
             pass 
             
    # Ensure it is a list
    if not isinstance(questions, list):
         questions = []
    
    # Strip correct answers for security
    safe_questions = []
    for q in questions:
        q_copy = q.copy()
        if 'correct_option' in q_copy:
            del q_copy['correct_option']
        safe_questions.append(q_copy)
        
    return render_template('attempt_quiz.html', quiz=quiz, questions=safe_questions)

@quiz_bp.route('/submit/<int:quiz_id>', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    try:
        quiz = Quiz.query.get_or_404(quiz_id)
        if not quiz.is_active:
            return jsonify({'error': 'Quiz Closed'}), 403

        # Check for existing submission
        if Score.query.filter_by(user_id=session['user_id'], quiz_id=quiz_id).first():
            return jsonify({'error': 'You have already submitted this quiz'}), 400
            
        user_answers = (request.get_json(silent=True) or {}).get('answers') # {q_id: option_index}
        
        # Decrypt Truth
        questions = aes.decrypt(quiz.questions_json)
        if isinstance(questions, str):
            questions = json.loads(questions)
        
        correct_count = 0
        streak = 0
        max_streak = 0
        
        # Basic Validation & Score
        correct_qids = []
        for q in questions:
            qid = str(q['id'])
            if qid in user_answers:
                 # Ensure we compare same types (str vs str or int vs int)
                 if int(user_answers[qid]) == int(q['correct_option']):
                    correct_count += 1
                    streak += 1
                    correct_qids.append(q['id'])
                 else:
                    max_streak = max(max_streak, streak)
                    streak = 0
        max_streak = max(max_streak, streak)
        
        # Calculate XP (Base + Streak + Difficulty)
        diff_map = json.loads(quiz.difficulty_map)
        difficulty_xp = sum(diff_map.get(str(qid), 1) for qid in correct_qids)
        
        base_xp = correct_count * 10
        streak_bonus = max_streak * 5
        total_xp = base_xp + streak_bonus + difficulty_xp

        # Auto-Sign Reward
        from crypto_utils import RSASigner
        signer = RSASigner()
        # Sign Achievement
        # --- [REQUIREMENT: Digital Signature using Hash] ---
        # Implementation: RSA-PSS signing of achievement metadata (User|Quiz|XP)
        data_to_sign = f"User:{session['user_id']}|Quiz:{quiz_id}|XP:{total_xp}"
        signature = signer.sign_data(data_to_sign)
        
        # Update User Total XP
        user = User.query.get(session['user_id'])
        
        # Logic: Only Players gain XP
        xp_gained_now = total_xp
        if user.role != 'player':
            xp_gained_now = 0
        
        if user.total_xp is None:
            user.total_xp = 0
        
        user.total_xp += xp_gained_now
        db.session.add(user) 

        # Encrypt Raw Score Data (JSON)
        score_data = {
            'correct_count': correct_count,
            'correct_qids': correct_qids,
            'user_answers': user_answers,
            'max_streak': max_streak,
            'xp_breakdown': {
                'base': base_xp,
                'streak': streak_bonus,
                'diff': difficulty_xp
            }
        }
        enc_score = aes.encrypt(json.dumps(score_data))

        score_entry = Score(
            user_id=session['user_id'],
            quiz_id=quiz_id,
            aes_score=enc_score,
            max_streak=max_streak,
            base64_signature=signature,
            xp_earned=xp_gained_now 
        )
        
        db.session.add(score_entry)
        db.session.commit()
        
        return jsonify({'message': f'Quiz Submitted! You earned {total_xp} XP.'})
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'message': f"Submission Error: {str(e)}"}), 500

@quiz_bp.route('/leaderboard')
def leaderboard():
    # Top 50 Users by XP (Descending) - PLAYERS ONLY
    # Exclude admins/moderators from global leaderboard as requested
    top_users = User.query.filter_by(role='player').order_by(User.total_xp.desc()).limit(50).all()
    return render_template('leaderboard.html', leaderboard=top_users)
