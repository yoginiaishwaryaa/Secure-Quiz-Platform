CREATE DATABASE secure_quiz;
USE secure_quiz;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE,
    password_hash VARCHAR(255),
    email VARCHAR(255),
    role ENUM('PLAYER','MODERATOR','ADMIN'),
    total_xp INT DEFAULT 0
);

CREATE TABLE quizzes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255),
    questions_enc BLOB,
    is_active BOOLEAN DEFAULT TRUE,
    end_time DATETIME
);

CREATE TABLE scores_rewards (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    quiz_id INT,
    aes_score BLOB,
    max_streak INT,
    base64_signature TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
