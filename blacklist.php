<?php
// Include necessary files for database connection
require_once 'db.php';

// Retrieve the IP address from POST data
$ip_address = $_POST['ip'];

// Prepare an SQL query to insert the IP into the blacklist table
$query = "INSERT INTO blacklist (ip_address) VALUES (?)";
$stmt = $link->prepare($query); // Use $link instead of $conn
$stmt->bind_param("s", $ip_address);

// Execute the query
if ($stmt->execute()) {
    // Redirect to admin page with success message
    header("Location: manageips.php?message=IP successfully blacklisted");
    exit();
} else {
    // Redirect to admin page with error message
    header("Location: manageips.php?message=Error blacklisting IP");
    exit();
}
?>
