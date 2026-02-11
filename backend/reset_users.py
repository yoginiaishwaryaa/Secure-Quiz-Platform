from app import create_app
from extensions import db
from models import User, Score, AccessRequest, AuditLog, Quiz

app = create_app()

with app.app_context():
    print("Starting cleanup of Players and Moderators...")
    
    # 1. Fetch target users
    users_to_delete = User.query.filter(User.role.in_(['player', 'moderator'])).all()
    count = len(users_to_delete)
    
    if count == 0:
        print("No players or moderators found.")
    else:
        for user in users_to_delete:
            print(f"Deleting user: {user.username} ({user.role})")
            
            # 2. Delete data tied to this user as a player/attendee
            Score.query.filter_by(user_id=user.id).delete()
            AccessRequest.query.filter_by(user_id=user.id).delete()
            AuditLog.query.filter_by(user_id=user.id).delete()
            
            # 3. If Moderator, delete quizzes they created + data linked to those quizzes
            if user.role == 'moderator':
                created_quizzes = Quiz.query.filter_by(created_by=user.id).all()
                for quiz in created_quizzes:
                    print(f"  - Deleting/Cascading quiz: {quiz.title}")
                    # Delete scores/requests for these quizzes (belonging to OTHER players)
                    Score.query.filter_by(quiz_id=quiz.id).delete()
                    AccessRequest.query.filter_by(quiz_id=quiz.id).delete()
                    db.session.delete(quiz)
            
            # 4. Delete the user
            db.session.delete(user)
        
        try:
            db.session.commit()
            print(f"Successfully deleted {count} users and their associated data.")
        except Exception as e:
            db.session.rollback()
            print(f"Error during commit: {e}")
