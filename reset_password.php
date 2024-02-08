
<?php
// Include the necessary files
include_once 'config.php';
include_once 'functions.php';

// Start session
session_start();

// Check if form is submitted
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Get the new password from the form
    $new_password = $_POST['new_password'];

    // Get the token from the form
    $token = $_POST['token'];

    // Reset the password
    $reset_successful = reset_password($token, $new_password);

    if ($reset_successful) {
        echo '<p class="text-success">Password reset successful! You can now <a href="index.php">log in</a> with your new password.</p>';
    } else {
        echo '<p class="text-danger">Password reset failed!</p>';
    }
}
?>

<!DOCTYPE html>
<html>
<head>
  <title>Reset Password</title>
  <link href='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css' rel='stylesheet'>
  <!-- TODO: Add additional CSS and JS as needed -->
</head>
<body>
  <div class='container'>
    <div class='row justify-content-center'>
      <div class='col-lg-5'>
        <div class='card shadow-lg border-0 rounded-lg mt-5'>
          <div class='card-header'>
            <h3 class='text-center font-weight-light my-4'>Reset Password</h3>
          </div>
          <div class='card-body'>
            <!-- Password Reset Form -->
            <form action='' method='POST'>
              <input type='hidden' name='token' value='<?= $_GET['token'] ?>'>
              <div class='form-group'>
                <label for='new_password'>New Password</label>
                <input type='password' id='new_password' name='new_password' class='form-control' required>
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
