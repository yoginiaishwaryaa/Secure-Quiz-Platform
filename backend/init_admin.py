from extensions import db, bcrypt
from models import User
from crypto_utils import RSASigner
import os

def init_admin():
    from app import create_app
    app = create_app()
    with app.app_context():
        print("Checking Admin Account...")
        username = "sysadmin"
        email = os.environ.get('ADMIN_EMAIL')
        password = os.environ.get('ADMIN_PASSWORD')

        if not email or not password:
            print("ERROR: ADMIN_EMAIL and ADMIN_PASSWORD must be set in .env")
            return
        
        admin = User.query.filter_by(role='admin').first()
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        if not admin:
            new_admin = User(
                username=username,
                email=email,
                password_hash=hashed_password,
                role='admin',
                total_xp=0
            )
            db.session.add(new_admin)
            db.session.commit()
            print(f"Admin account created: {email}")
        else:
            # Update Email if changed
            if admin.email != email:
                print(f"Updating Admin email from {admin.email} to {email}")
                admin.email = email
            
            # Always ensure password matches .env (Force Update)
            if not bcrypt.check_password_hash(admin.password_hash, password):
                print("Updating Admin password to match .env")
                admin.password_hash = hashed_password
            
            admin.is_approved = True # Ensure existing admin is approved
            db.session.commit()
            print(f"Admin account confirmed and approved: {admin.email}")
            
        # Key Generation (Certificate Authority)
        print("Initializing RSA Keys (CA Layer)...")
        signer = RSASigner() # This auto-generates keys if missing
        print(f"Keys ensured at: {signer.key_dir}")
        print("Setup Complete.")

if __name__ == '__main__':
    init_admin()
