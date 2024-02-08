<?php

require_once 'db.php';
require_once 'functions.php';

session_start();

 // Get the current year
 $currentYear = date('Y');

//rate_limting DDoS
//$user_ip = $_SERVER['REMOTE_ADDR'];
//rate_limiting($user_ip);

// Get the full URL
$url = $_SERVER['REQUEST_URI'];

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


//session_start();

// Prevent session hijacking
prevent_session_hijacking();

// CSRF token
//if ($_SERVER["REQUEST_METHOD"] == "POST") {
  //  if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] != $_SESSION['csrf_token']) {
    //    die("CSRF token mismatch.");
    //}
//}
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$csrf_token = $_SESSION['csrf_token'];

// Check if the user's IP is in the blacklist
$user_ip = $_SERVER['REMOTE_ADDR'];
$query_blacklist = "SELECT * FROM blacklist WHERE ip_address = ?";
$stmt_blacklist = $link->prepare($query_blacklist);
$stmt_blacklist->bind_param("s", $user_ip);
$stmt_blacklist->execute();
$result_blacklist = $stmt_blacklist->get_result();

if ($result_blacklist->num_rows > 0) {
    // Redirect to banned.php if the IP is in the blacklist
    header("Location: banned.php");
    exit();
}


/////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////
// Login logic

if (isset($_POST['username']) && isset($_POST['password'])) {
    $username = sanitize_input($_POST['username']);
    $password = sanitize_input($_POST['password']);

    $sql = "SELECT id, username, password FROM users WHERE username = '$username'";
    $result = mysqli_query($link, $sql);

    if ($result && mysqli_num_rows($result) > 0) {
        $row = mysqli_fetch_assoc($result);
        if (password_verify($password, $row['password'])) {
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['username'] = $row['username'];

// Generate a random 5-digit OTP
    $verification_code = rand(10000, 99999);

    // Insert the Verification into the database along with the user ID and timestamp
    $verification_code_query = "INSERT INTO admin_verification_codes (user_id, code, timestamp) VALUES (?, ?, NOW())";
    $verification_code_stmt = $link->prepare($verification_code_query);
    $verification_code_stmt->bind_param("ii", $_SESSION['user_id'], $verification_code);
    $verification_code_stmt->execute();
    $verification_code_stmt->close();

    // Prepare the email subject and body
    $email_subject = "Verification Code";
    $email_body = "Your Code is: " . $verification_code;

    // Use PHPMailer to send the OTP to the admin email
    send_email_to_admin($email_subject, $email_body);
        
    // Redirect the admin to the verification page
    header('Location: verification.php');
    exit();
           // header('Location: admin.php');
            //exit();
        } else {
            $login_error = "Incorrect username or password";
            log_failed_attempt($_SERVER['REMOTE_ADDR']); // Call the function here
        }
    } else {
        $login_error = "Incorrect username or password";
        log_failed_attempt($_SERVER['REMOTE_ADDR']); // And here
    }
}



// File inclusion logic
if (isset($_GET['file'])) {
    $file_path = sanitize_input($_GET['file']);
    if (!check_file_inclusion($file_path)) {
        die("File inclusion attempt blocked.");
    }
    include($file_path);
}

// Command injection example
if (isset($_POST['command'])) {
    $command = sanitize_input($_POST['command']);
    if (!check_command_injection($command)) {
        die("Command injection attempt blocked.");
    }
    $command_output = shell_exec($command);
}

?>


<!DOCTYPE html>
<html lang="en">
<meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>waf</title>
    <style>
        /* Style to make the video fill the entire viewport */
        body, html {
            height: 100%;
            margin: 0;
        }
        
        .video-background {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
            z-index: -1;
            background: url('sm1.jpg') no-repeat center center;
            background-size: cover;
         }

        .txt{

            color:white;
        }

        body, h1 {
        color: white;
        }

        .content {
            position: relative;
            z-index: 1;
        }

         /* Style for the copyright notice */
        .copyright {
            position: fixed;
            bottom: 0;
            left: 0;
            width: 100%;
            /*background-color: black; /* Background color for the copyright bar */
            color: white; /* Text color is white */
            text-align: center;
            padding: 10px 0;
        }
    </style>
</head>
<body>
    <!-- Video Background -->
    <div class="video-background">
        <video autoplay muted loop>
            <source src="backgroundvid.mp4" type="video/mp4">
            Your browser does not support the video tag.
        </video>
    </div>




    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Application Firewall</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
.logo {
    display: block;
    margin: 0 auto 2px; /* Center the logo and add a 10px margin below it */
}
        .center-form {
            position: absolute;
            top: 45%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 300px;
        }
    </style>
</head>
<body>

    
    <div class="center-form">
    <h1 class="text-center"><img src="" alt="" class="logo">Web  Application  Firewall</h1>
        <form action="index.php" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
            <div class="form-group">
                <label for="username" class = 'txt'>Username:</label>
                <input type="text" name="username" id="username" class="form-control">
            </div>
            <div class="form-group">
                <label for="password" class = 'txt' >Password:</label>
                <input type="password" name="password" id="password" class="form-control">
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        
<div class="form-group">
  <a href="forgot_password.php" class = 'txt' >Forgot password?</a>
</div>
</form>
    </div>
    
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>

<script type="text/javascript">
    function toggleLanguageDropdown() {
        var dropdown = document.getElementById('language-dropdown');
        dropdown.style.display = (dropdown.style.display === 'none') ? 'block' : 'none';
    }
</script>

<!-- Display the copyright notice -->
    <div class="copyright">
        &copy; <?php echo $currentYear; ?> David Daka. All rights reserved.
    </div>

</body>
</html>


