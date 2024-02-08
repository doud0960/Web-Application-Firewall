
<?php
// Include the necessary files
include_once 'config.php';
include_once 'functions.php';

// Start session
session_start();

// Check if form is submitted
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Get the email from the form
    $email = $_POST['email'];

    // Handle the password reset request
    $token = handle_password_reset_request($email);

    if ($token) {
        // Send the password reset email
        send_password_reset_email($email, $token);
    } else {
        // Email not found in the database
        echo '<p class="text-danger">Email not found!</p>';
    }
}


// Check if form is submitted
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // TODO: Handle password reset request
    // 1. Validate email address
    // 2. Generate a unique password reset token
    // 3. Save the token in the database
    // 4. Send an email to the user with the password reset link
}
?>

<!DOCTYPE html>
<html>
<head>
  <title>Password Reset</title>
  <link href='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css' rel='stylesheet'>
  <!-- TODO: Add additional CSS and JS as needed -->
</head>
<body>
  <div class='container'>
    <div class='row justify-content-center'>
      <div class='col-lg-5'>
        <div class='card shadow-lg border-0 rounded-lg mt-5'>
          <div class='card-header'>
            <h3 class='text-center font-weight-light my-4'>Password Recovery</h3>
          </div>
          <div class='card-body'>
            <!-- Password Reset Form -->
            <form action='' method='POST'>
              <div class='form-group'>
                <label for='email'>Email Address</label>
                <input type='email' id='email' name='email' class='form-control' required>
              </div>
              <div class='form-group d-flex align-items-center justify-content-between mt-4 mb-0'>
                <button type='submit' class='btn btn-primary'>Reset Password</button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>
