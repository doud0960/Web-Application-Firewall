<?php

require_once 'db.php';
require_once 'functions.php';

session_start();

define('CODE_EXPIRY_DURATION', 60); // 300 seconds means 5 minutes


// After initializing the session and other checks

// Check if the resend form was submitted
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['resend_code'])) {
    // Perform CSRF check
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] != $_SESSION['csrf_token']) {
        die("CSRF token mismatch.");
    }
    
    // Throttle check (optional, recommended)
    // Ensure user cannot request codes too frequently, e.g., not more than once every 60 seconds
    if (!canResendCode($user_id)) { // You'll need to implement this function
        die("You must wait before requesting a new code.");
    }

    // Generate a new verification code
    $verification_code = rand(10000, 99999);

    // Save the new code to the database with the current timestamp
    $verification_code_query = "REPLACE INTO admin_verification_codes (user_id, code, timestamp) VALUES (?, ?, NOW())";
    $verification_code_stmt = $link->prepare($verification_code_query);
    $verification_code_stmt->bind_param("ii", $_SESSION['user_id'], $verification_code);
    $verification_code_stmt->execute();
    $verification_code_stmt->close();

    // Send the new code via email
    $email_subject = "New Verification Code";
    $email_body = "Your new code is: " . $verification_code;
    send_email_to_admin($email_subject, $email_body);

    // Provide feedback to the user
    $resend_success = "A new verification code has been sent to your email.";
}


// Verification logic
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $entered_code = sanitize_input($_POST['verification_code']);
    $user_id = $_SESSION['user_id']; // Assumed to be stored in the session from the login process

    // Retrieve the latest verification code for the user from the database
    $verification_code_query = "SELECT code, timestamp FROM admin_verification_codes WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1";
    $verification_code_stmt = $link->prepare($verification_code_query);
    $verification_code_stmt->bind_param("i", $user_id);
    $verification_code_stmt->execute();
    $result = $verification_code_stmt->get_result();
    $verification_code_stmt->close();

    if ($result && $result->num_rows > 0) {
        $verification_data = $result->fetch_assoc();
        $valid_code = $verification_data['code'];
        $code_timestamp = strtotime($verification_data['timestamp']);

        // Check if the code matches and is not expired
        if ($entered_code == $valid_code && time() - $code_timestamp < CODE_EXPIRY_DURATION) {
            // Set session variables to confirm the user is fully authenticated
            $_SESSION['is_verified'] = true;

            // Redirect to the protected area
            header('Location: admin.php');
            exit();
        } else {
            // Handle error: code mismatch or expired
            $error_message = "Invalid or expired verification code.";
            // Optionally, provide a way to resend the code
        }
    } else {
        // Handle error: no code found for the user
        $error_message = "No verification code found. Please request a new code.";
    }
}



?>

<!-- HTML for verification form -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Your Identity</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .center-form {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 400px;
            background: #fff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .form-group {
            margin-bottom: 15px;
        }
        .error {
            color: #d9534f; /* Bootstrap's danger color */
        }
        .btn-link {
            font-weight: bold;
            color: #007bff; /* Bootstrap's primary color */
            text-decoration: none;
            margin-top: 15px;
        }
        .btn-link:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>

    <!-- ... Your existing HTML ... -->
    
    <div class="center-form">
        <h1 class="text-center">Verification Code</h1>
        <?php if (isset($resend_success)) echo "<p class='alert alert-success'>$resend_success</p>"; ?>
        <?php if (isset($error_message)) echo "<p class='alert alert-danger'>$error_message</p>"; ?>
        
        <form action="verification.php" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
            <div class="form-group">
                <label for="verification_code">Enter the code sent to your email:</label>
                <input type="text" name="verification_code" id="verification_code" class="form-control" required>
            </div>
            <button type="submit" class="btn btn-primary btn-block">Verify</button>
        </form>
        <form action="verification.php" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
            <input type="hidden" name="resend_code" value="1">
            <button type="submit" class="btn btn-link btn-block">Resend Code</button>
        </form>
    </div>

    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>

</body>
</html>
