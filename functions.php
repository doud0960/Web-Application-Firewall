<?php

require_once 'includes/PHPMailer.php';
require_once 'includes/SMTP.php';
require_once 'includes/Exception.php';

// Get the full URL
$url = $_SERVER['REQUEST_URI'];


function sanitize_input($data) {
    global $link;

    $data = trim($data); // Remove leading and trailing whitespace
    $data = stripslashes($data); // Remove backslashes
    $data = htmlspecialchars($data); // Convert special characters to HTML entities
    $data = mysqli_real_escape_string($link, $data); // Escape characters for SQL query
    return $data;
}

include_once 'config.php';

// Function to check if a user is authenticated as an admin
// Redirects to the login page if the user is not authenticated or is not an admin
function check_admin_auth() {
    // Start session if it hasn't been started already
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    // If the user isn't logged in or isn't an admin, redirect to index.php (login page)
    if (!isset($_SESSION['user_id']) || (isset($_SESSION['username']) && $_SESSION['username'] != 'admin')) {
        header('Location: index.php');
        exit();
    }
    if (!isset($_SESSION['user_id'])) {
        die("Authentication required."); // Stop execution if user is not authenticated
    }
}

// Check for file inclusion attacks
function check_file_inclusion($path) {
    $allowed_paths = ["path/to/allowed/file1", "path/to/allowed/file2"];
    return in_array($path, $allowed_paths); // Return true if the path is in the list of allowed paths
}

// Check for command injection attacks
function check_command_injection($command) {
    $blacklist = ["rm", "ls", "cat"]; // Blacklisted commands
    foreach ($blacklist as $item) {
        if (strpos($command, $item) !== false) {
            return false; // Return false if the command contains a blacklisted item
        }
    }
    return true;
}

// Block PHP object injection attempts
function block_php_object_injection($data) {
    $tokens = token_get_all($data);
    foreach ($tokens as $token) {
        if (is_array($token) && $token[0] == T_NEW) {
            die("PHP object injection attempt blocked."); // Stop execution if object instantiation is detected
        }
    }
}

// Prevent session hijacking by checking IP and User-Agent
function prevent_session_hijacking() {
    if (isset($_SESSION['user_ip']) && $_SESSION['user_ip'] != $_SERVER['REMOTE_ADDR'] ||
        isset($_SESSION['user_agent']) && $_SESSION['user_agent'] != $_SERVER['HTTP_USER_AGENT']) {
        session_destroy(); // Destroy session if IP or User-Agent doesn't match
        die("Session hijacking attempt detected.");
    }
    $_SESSION['user_ip'] = $_SERVER['REMOTE_ADDR'];
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
}

// Validate file uploads based on type and size
function validate_file_upload($file) {
    $allowed_file_types = ['image/jpeg', 'image/png']; // Allowed file types
    if (!in_array($file['type'], $allowed_file_types)) {
        die("Invalid file type."); // Stop execution if file type is not allowed
    }
    if ($file['size'] > 500000) { // Example size: 500KB
        die("File too large."); // Stop execution if file size exceeds the limit
    }
}

// Handle password reset request
function handle_password_reset_request($email) {
    global $link;

    // Sanitize email
    $email = sanitize_input($email);

    // Check if the email exists in the database
    
$user_ip = $_SERVER['REMOTE_ADDR'];

// Query to check if the IP is in the blacklist
$query = "SELECT * FROM blacklist WHERE ip_address = ?";
$stmt = $link->prepare($query);
$stmt->bind_param("s", $user_ip);
$stmt->execute();
$result = $stmt->get_result();

// If the IP is in the blacklist, redirect to an error page
if ($result->num_rows > 0) {
    header("Location: banned.php");
    exit();
}

// Continue with the normal login process

// Query to check if the IP is in the whitelist (only if you want to enforce whitelist access)
$query = "SELECT * FROM whitelist WHERE ip_address = ?";
$stmt = $link->prepare($query);
$stmt->bind_param("s", $user_ip);
$stmt->execute();
$result = $stmt->get_result();

// If the IP is not in the whitelist, redirect to an error page
if ($result->num_rows == 0) {
    header("Location: not_whitelisted.php");
    exit();
}
$query = "SELECT * FROM users WHERE email = '$email'";
    $result = mysqli_query($link, $query);
    if (mysqli_num_rows($result) == 0) {
        // Email not found in the database
        return false;
    }

    // Generate a unique password reset token
    $token = bin2hex(random_bytes(50));

    // Save the token in the database
    $timestamp = date('Y-m-d H:i:s');
    $query = "INSERT INTO password_resets (email, token, timestamp) VALUES ('$email', '$token', '$timestamp')";
    mysqli_query($link, $query);

    // Return the token for use in the email
    return $token;
}



use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Send a password reset email
function send_password_reset_email($email, $token) {
   
    // Create a new PHPMailer instance
    $mail = new PHPMailer();

    // Server settings
    $mail->isSMTP();
    $mail->SMTPDebug = 2;
    $mail->Host = "smtp.gmail.com";
    $mail->Port = "587";
    $mail->SMTPSecure = "tls";
    $mail->SMTPAuth = true;
    $mail->Username = "emailaddr";
    $mail->Password = "apppassword";

    // Recipients
    $mail->setFrom('emailaddr', 'name');
    $mail->addAddress($email);

    // Content
    $mail->isHTML(true);
    $mail->Subject = 'Password Reset Request';
    $mail->Body    = "Click on this <a href='http://localhost/temp/reset_password.php?token=$token'>link</a> to reset your password.";

    // Send the email
    if(!$mail->send()) {
        echo "Message could not be sent.";
    } else {
        echo 'Password reset link has been sent to your email address.';
    }
}


// Reset the user's password
function reset_password($token, $new_password) {
    global $link;

    // Sanitize the new password
    $new_password = sanitize_input($new_password);

    // Hash the new password
    $new_password_hashed = password_hash($new_password, PASSWORD_DEFAULT);

    // Get the email associated with the token
    $query = "SELECT email FROM password_resets WHERE token = '$token'";
    $result = mysqli_query($link, $query);
    if (mysqli_num_rows($result) == 0) {
        // Token not found in the database
        return false;
    }
    $email = mysqli_fetch_assoc($result)['email'];

    // Update the password in the database
    $query = "UPDATE users SET password = '$new_password_hashed' WHERE email = '$email'";
    mysqli_query($link, $query);

    // Delete the token from the database
    $query = "DELETE FROM password_resets WHERE token = '$token'";
    mysqli_query($link, $query);

    return true;
}


// Function to log attack
function log_attack($attack_type, $user_ip) {
    global $link;

    // Insert the attack details into the database
    $stmt = $link->prepare("INSERT INTO attack_logs (attack_type, user_ip, timestamp) VALUES (?, ?, NOW())");
    $stmt->bind_param("ss", $attack_type, $user_ip);
    $stmt->execute();
    $stmt->close();

    // Send email notification to admin
    $subject = "WAF Alert: Attack Attempt Detected";
    $message = "Attack Type: " . $attack_type . "\nUser IP: " . $user_ip . "\nTimestamp: " . date('Y-m-d H:i:s');
    send_email_to_admin($subject, $message);
}

  //sending attack alerts to admin's email.   
function send_email_to_admin($subject, $message) {
     // Create a new PHPMailer instance
     $mail = new PHPMailer();

     // Server settings
     $mail->isSMTP();
     $mail->SMTPDebug = 2;
     $mail->Host = "smtp.gmail.com";
     $mail->Port = "587";
     $mail->SMTPSecure = "tls";
     $mail->SMTPAuth = true;
     $mail->Username = "emailaddr";
     $mail->Password = "apppassword";
 

    $mail->setFrom('emailaddr', 'WAF');
    $mail->addAddress('emailaddr'); // Admin's email address

    $mail->isHTML(true);
    $mail->Subject = $subject;
    $mail->Body = $message;

    if (!$mail->send()) {
        // Handle the error if the email is not sent
        echo 'Mailer Error: ' . $mail->ErrorInfo;
    } else {
        // Email sent successfully
        echo 'Message sent!';
    }
}
 
 // Define a regex pattern to detect suspicious characters often used in SQL injection
$pattern = '#[;\'"()]+#';

// Assuming password is retrieved from POST data
if (isset($_POST['password'])) {
    $password = $_POST['password'];
} else {
    $password = ""; // Set a default value or handle the error
}
if (isset($_POST['username'])) {
    $username = $_POST['username'];
} else {
    $username = ""; // Set a default value or handle the error
}

// Check for suspicious patterns indicating an SQL injection attempt
if (preg_match($pattern, $username) || preg_match($pattern, $password)) {
    // Log the attack
    log_attack('SQL Injection', $_SERVER['REMOTE_ADDR']);
    
    // Send email notification to admin
    send_email_to_admin('SQL Injection Attempt Detected', 'Potential SQL injection attempt was detected from IP: ' . $_SERVER['REMOTE_ADDR']);
    
    // Redirect to an error page or show an error message
    die('Suspicious activity detected. The incident has been logged.');
}

 // Define a regex pattern to detect suspicious characters often used in XSS attack
 $patt = [
    '#<script(.*?)>#is',          // Script tags
    '#on[a-z]+\s*=\s*["\'](.*?)["\']#is', // JavaScript events like onclick
    '#javascript\s*:#is',         // JavaScript pseudo-protocol
    '#<iframe(.*?)>#is',          // iFrame tags
    '#<applet(.*?)>#is',          // Applet tags
    '#<object(.*?)>#is',          // Object tags
    '#<embed(.*?)>#is',           // Embed tags
    '#<form(.*?)>#is',            // Form tags that might have an action that is javascript
    '#<img\s+[^>]*src\s*=\s*["\']?javascript#is', // IMG tags with JavaScript in SRC
    '#<link(.*?)>#is',            // Link tags
    '#<meta(.*?)>#is',            // Meta tags
    '#<style(.*?)>#is',           // Style tags
    '#<body[^>]*onload(.*?)>#is', // Body tags with onload events
    '#<svg/onload(.*?)>#is',      // SVG onload events
    '#<div\s+[^>]*style\s*=\s*["\']?expression#is', // CSS expressions
    '#data\s*:\s*image#is',       // Data URLs
    '#<base(.*?)>#is'             // Base tags
    // Add more patterns as needed
];


// Assuming password and username are retrieved from POST data
$password = $_POST['password'] ?? ""; // Using null coalescing operator to set default value
$username = $_POST['username'] ?? "";

// Function to check for suspicious patterns indicating an XSS attempt
function check_xss($input, $patterns) {
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $input)) {
            return true; // Pattern found, potential XSS attempt
        }
    }
    return false; // No patterns found, input seems safe
}

// Check for suspicious patterns indicating XSS attempt
if (check_xss($username, $patt) || check_xss($password, $patt)) {
    // Log the attack
    log_attack('Cross-Site Scripting', $_SERVER['REMOTE_ADDR']);
    
    // Send email notification to admin
    send_email_to_admin('XSS Attempt Detected', 'Potential XSS attempt was detected from  IP: ' . $_SERVER['REMOTE_ADDR']);
    
    // Redirect to an error page or show an error message
    die('Suspicious activity detected. The incident has been logged.');
}

function log_failed_attempt($ip_address) {
    global $link; // Assuming $link is your database connection

    // Log the failed attempt
    $query = "INSERT INTO failed_login_attempts (ip_address) VALUES (?)";
    $stmt = $link->prepare($query);
    $stmt->bind_param("s", $ip_address);
    $stmt->execute();

    // Check for 3 or more failed attempts in the last 10 seconds
    $query = "SELECT COUNT(*) FROM failed_login_attempts WHERE ip_address = ? AND attempt_time >= (NOW() - INTERVAL 20 SECOND)";
    $stmt = $link->prepare($query);
    $stmt->bind_param("s", $ip_address);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_row();

    //>>> initial
    if ($row[0] >= 3) {
        // Block the IP
        $query = "UPDATE failed_login_attempts SET is_blocked = TRUE WHERE ip_address = ?";
        $stmt = $link->prepare($query);
        $stmt->bind_param("s", $ip_address);
        $stmt->execute();

        $attack_type = "Brute Force";
        $query = "INSERT INTO attack_logs (attack_type, user_ip, timestamp) VALUES (?, ?, NOW())";
        $stmt = $link->prepare($query);
        $stmt->bind_param("ss", $attack_type, $ip_address);
        $stmt->execute();

        // Send email notification to admin
        send_email_to_admin('Brute Force Attempt Detected', 'Potential brute force attempt was detected from IP: ' . $ip_address);
        
        die('Your IP has been blocked due to suspicious activity.');

         // Log the brute force attack in the attack_logs table
        
    }
}

function log_request($ip_address) {
    global $link;

    // Log the request
    $query_log = "INSERT INTO rate_limiting (ip_address) VALUES (?)";
    $stmt_log = $link->prepare($query_log);
    $stmt_log->bind_param("s", $ip_address);
    $stmt_log->execute();
    $stmt_log->close();

    // Check for excessive requests (e.g., more than 100 requests in the last minute)
    $query_check = "SELECT COUNT(*) as count FROM rate_limiting WHERE ip_address = ? AND timestamp > DATE_SUB(NOW(), INTERVAL 1 MINUTE)";
    $stmt_check = $link->prepare($query_check);
    $stmt_check->bind_param("s", $ip_address);
    $stmt_check->execute();
    $result_check = $stmt_check->get_result();
    $row_check = $result_check->fetch_assoc();
    $stmt_check->close();

    // If the request limit is exceeded, send an email alert to the admin
    //100 initial
    if ($row_check['count'] > 20) {
        send_email_to_admin('DDoS Attempt Detected', 'Potential DDoS attempt detected from IP: ' . $ip_address);
    }
}


function rate_limiting($user_ip) {
    global $link;

    // Fetch current settings for max_requests and time_period from the database
    $settings_query = "SELECT max_requests, time_period FROM rate_limiting_settings WHERE id = 1";
    $settings_result = mysqli_query($link, $settings_query);
    $settings = mysqli_fetch_assoc($settings_result);
    
    // If settings are not set, use default values
    $max_requests = $settings['max_requests'] ?? 20;
    $time_period = $settings['time_period'] ?? 60;

    // Query the database to get the last request time and request count for the given IP
    $query = "SELECT last_request_time, request_count FROM rate_limiting WHERE ip_address = ?";
    $stmt = $link->prepare($query);
    $stmt->bind_param("s", $user_ip);
    $stmt->execute();
    $stmt->bind_result($last_request_time, $request_count);
    $stmt->fetch();
    $stmt->close();

    // If the IP address is not found or the time period has expired, insert or update the record
    if (!$last_request_time || time() - strtotime($last_request_time) > $time_period) {
        $query = "REPLACE INTO rate_limiting (ip_address, last_request_time, request_count) VALUES (?, NOW(), 1)";
        $stmt = $link->prepare($query);
        $stmt->bind_param("s", $user_ip);
        $stmt->execute();
        $stmt->close();
    } else {
        // If the request count exceeds the maximum allowed, log the attack and redirect to an error page
        if ($request_count >= $max_requests) {
            log_attack('DDoS Attack', $user_ip);
            send_email_to_admin('DDoS Attempt Detected', 'Potential DDoS attempt was detected from IP: ' . $user_ip);
            die('Rate limit exceeded. The incident has been logged.');
        }

        // Increment the request count
        $query = "UPDATE rate_limiting SET request_count = request_count + 1, last_request_time = NOW() WHERE ip_address = ?";
        $stmt = $link->prepare($query);
        $stmt->bind_param("s", $user_ip);
        $stmt->execute();
        $stmt->close();
    }
}

function canResendCode($user_id) {
    global $link;

    // Query the database for the last code's timestamp
    $query = "SELECT timestamp FROM admin_verification_codes WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1";
    $stmt = $link->prepare($query);
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $stmt->bind_result($last_timestamp);
    $stmt->fetch();
    $stmt->close();

    // Check if enough time has passed since the last code was sent
    return !$last_timestamp || (time() - strtotime($last_timestamp) > 60); // 60 seconds
}


    // Directory Traversal Check
if (preg_match('/\.\.\//', $url) || preg_match('/\.\.\\\\/', $url)) {
    // Log the attack
    $attack_type = "Directory Traversal";
    $user_ip = $_SERVER['REMOTE_ADDR'];
    $query = "INSERT INTO attack_logs (attack_type, user_ip, timestamp) VALUES ('$attack_type', '$user_ip', NOW())";
    mysqli_query($link, $query);

    // Send alert (use your existing alert function)
    send_email_to_admin('Directory Traversal Attack Detected', 'A directory traversal attack attempt was detected from IP: ' . $user_ip);

    // Prevent further execution
    exit("Directory traversal attack detected. Access denied.");
}



function createRule($link, $name, $type, $pattern, $action, $status) {
    $query = "INSERT INTO waf_rules (name, type, pattern, action, status) VALUES (?, ?, ?, ?, ?)";
    $stmt = $link->prepare($query);
    $stmt->bind_param("sssss", $name, $type, $pattern, $action, $status);
    $stmt->execute();
    $stmt->close();
}

function getRules($link) {
    $query = "SELECT * FROM waf_rules";
    $result = $link->query($query);
    $rules = [];
    while($row = $result->fetch_assoc()) {
        $rules[] = $row;
    }
    return $rules;
}

function getRule($link, $id) {
    $query = "SELECT * FROM waf_rules WHERE id = ?";
    $stmt = $link->prepare($query);
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $rule = $result->fetch_assoc();
    $stmt->close();
    return $rule;
}

function updateRule($link, $id, $name, $type, $pattern, $action, $status) {
    $query = "UPDATE waf_rules SET name = ?, type = ?, pattern = ?, action = ?, status = ? WHERE id = ?";
    $stmt = $link->prepare($query);
    $stmt->bind_param("sssssi", $name, $type, $pattern, $action, $status, $id);
    $stmt->execute();
    $stmt->close();
}

function deleteRule($link, $id) {
    $query = "DELETE FROM waf_rules WHERE id = ?";
    $stmt = $link->prepare($query);
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $stmt->close();
}
