import os
from flask import Flask, render_template, redirect, url_for, session
from config import Config
from extensions import db, bcrypt, mail

def create_app(config_class=Config):
    app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')
    app.config.from_object(config_class)

    # Initialize Extensions
    db.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)

    # Automatic Database Creation
    with app.app_context():
        try:
            # Create DB if not exists
            import pymysql
            conn = pymysql.connect(
                host=os.environ.get('MYSQL_HOST'),
                user=os.environ.get('MYSQL_USER'),
                password=os.environ.get('MYSQL_PASSWORD')
            )
            cursor = conn.cursor()
            db_name = os.environ.get('MYSQL_DB')
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
            conn.close()
        except Exception as e:
            print(f"DB Setup Error (Ignore if DB exists/permissions): {e}")

    # Register Blueprints
    from routes.auth import auth_bp
    from routes.quiz_routes import quiz_bp
    from routes.admin_routes import admin_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(quiz_bp, url_prefix='/quiz')
    app.register_blueprint(admin_bp, url_prefix='/admin')

    # Root route for redirection/landing
    @app.route('/')
    def index():
        if session.get('user_id'):
            role = session.get('role')
            if role == 'admin':
                return redirect(url_for('admin.dashboard'))
            elif role == 'moderator':
                return redirect(url_for('quiz.moderator_dashboard'))
            else:
                return redirect(url_for('quiz.player_dashboard'))
        return render_template('landing.html')

    # Create Database Tables
    with app.app_context():
        db.create_all()

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
