<?php
// Database connection (replace with your connection details)
require_once 'db.php';
$link = mysqli_connect('localhost', 'root', '', 'waf');

// New password
$new_password = ""; // Choose a new strong password
$hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

// Admin username
$username = "admin";

// SQL query to update the password
$sql = "UPDATE users SET password = '$hashed_password' WHERE username = '$username'";
$result = mysqli_query($link, $sql);

if ($result) {
    echo "Password updated successfully.";
} else {
    echo "Error updating password: " . mysqli_error($link);
}
?>
