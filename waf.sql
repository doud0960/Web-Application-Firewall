CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'user') NOT NULL
);
INSERT INTO users (username, email, password, role) VALUES ('', '', SHA2('', 256), 'admin');

CREATE TABLE admin (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50),
    password VARCHAR(255)
);
ALTER TABLE admin ADD COLUMN role VARCHAR(20);


CREATE TABLE attack_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    attack_type VARCHAR(255),
    user_ip VARCHAR(40),
    timestamp DATETIME
);



CREATE TABLE password_resets (
    id INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL,
    token VARCHAR(100) NOT NULL,
    timestamp DATETIME NOT NULL
);

CREATE TABLE failed_login_attempts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_blocked BOOLEAN DEFAULT FALSE
);

CREATE TABLE whitelist (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE blacklist (
    id INT PRIMARY KEY AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);



CREATE TABLE rate_limiting_settings (
    id INT PRIMARY KEY AUTO_INCREMENT,
    max_requests INT NOT NULL,
    time_period INT NOT NULL
);

-- Table for logging all incoming requests
CREATE TABLE request_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_ip VARCHAR(40),
    request_type VARCHAR(10),
    request_url VARCHAR(255),
    user_agent VARCHAR(255),
    timestamp DATETIME
);

-- Table for storing aggregated daily statistics
CREATE TABLE daily_stats (
    id INT PRIMARY KEY AUTO_INCREMENT,
    total_requests INT,
    total_attacks INT,
    total_blocks INT,
    date DATE
);

CREATE TABLE waf_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50),
    pattern TEXT,
    action ENUM('block', 'allow', 'log') DEFAULT 'block',
    status ENUM('active', 'inactive') DEFAULT 'active'
);
CREATE TABLE admin_verification_codes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  code INT NOT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE rate_limiting (
    ip_address VARCHAR(45) NOT NULL,
    last_request_time TIMESTAMP NOT NULL,
    request_count INT NOT NULL,
    PRIMARY KEY (ip_address)
);
