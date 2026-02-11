# Secure Gamified Quiz & Reward System

A high-integrity, web-based platform designed to facilitate quizzes with automated, tamper-proof rewards in the form of XP. Compliant with NIST SP 800-63-2 and utilizing Hybrid Cryptography (AES+RSA).

## Features
- **RBAC**: Player, Moderator, Admin roles.
- **MFA**: Email/Console OTP.
- **Security**: 
  - AES-256 Encryption for stored Questions and Answers.
  - RSA-2048 Digital Signatures for XP Rewards.
- **Gamification**:
  - Streak Bonuses.
  - Difficulty-weighted scoring.
  - Leaderboards.

## Directory Structure
- `backend/`: Flask application, API routes, Crypto logic.
- `frontend/`: HTML templates and CSS.

## Quick Start
1. Update `backend/.env` with your MySQL credentials.
2. Install requirements: `pip install -r backend/requirements.txt`.
3. Run: `python backend/app.py`.
