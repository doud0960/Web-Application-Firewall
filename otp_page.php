<?php
// Initialize the session
session_start();

// Include database configuration
require_once "db.php";

// Check if OTP is already verified
if (isset($_SESSION['otp_verified']) && $_SESSION['otp_verified'] === true) {
    header('Location: admin.php');
    exit();
}

// Processing form data when form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $submitted_otp = $_POST['otp'];

    // Fetch the OTP and timestamp from the database for the user
    $query = "SELECT otp, timestamp FROM admin_otp WHERE user_id = ?";
    $stmt = $link->prepare($query);
    $stmt->bind_param("i", $_SESSION['user_id']);
    $stmt->execute();
    $stmt->bind_result($stored_otp, $stored_timestamp);
    $stmt->fetch();
    $stmt->close();

    $current_time = new DateTime();
    $otp_time = new DateTime($stored_timestamp);

    // Check if the OTP is expired (5 minutes in this example)
    $interval = $current_time->diff($otp_time);
    $elapsed_time = ($interval->i * 60) + $interval->s;

    // Debugging information
    echo "Stored OTP: " . $stored_otp . "<br>";
    echo "Submitted OTP: " . $submitted_otp . "<br>";
    
    // Initialize current time
    $current_time = new DateTime();

    // Calculate elapsed time
    $elapsed_time = ($interval->i * 60) + $interval->s;
    echo "Elapsed Time: " . $elapsed_time . " seconds<br>";

    // Validate the OTP and check if it's expired
    //Initial 300
    if ($submitted_otp == $stored_otp && $elapsed_time <= 300) {
        // OTP is correct and not expired
        $_SESSION['otp_verified'] = true;
        header('Location: admin.php');
        exit();
    } else {
        // OTP is incorrect or expired
        // Show an error message or resend the OTP
        $error = "Invalid or expired OTP";
    }
}

?>

<!-- HTML part for OTP form -->

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>OTP Verification</title>
    <!-- Bootstrap CSS -->
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <!-- Custom CSS -->
    <style>
        body { 
            background-color: #f8f9fa;
            margin-top: 100px;
        }
        .container {
            max-width: 400px;
        }
    </style>
</head>
<body>
    <div class="container">

<html>
<head>
    <title>OTP Verification</title>
</head>
<body>
    <h2>Enter the OTP sent to your email</h2>
    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
        <input type="text" name="otp" required>
        <input type="submit" value="Verify OTP">
    </form>
    <?php
    if (!empty($error)) {
        echo '<p>' . $error . '</p>';
    }
    ?>

    </div>
    <!-- Optional JavaScript -->
    <!-- Bootstrap JS (Optional) -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.3/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>

</html>
