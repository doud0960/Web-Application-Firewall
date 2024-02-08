<?php
// Include necessary files for database connection
require_once 'db.php';

// Retrieve the IP address from POST data
$ip_address = $_POST['ip'];

// Prepare an SQL query to insert the IP into the whitelist table
$query = "INSERT INTO whitelist (ip_address) VALUES (?)";
$stmt = $link->prepare($query);
$stmt->bind_param("s", $ip_address);

// Execute the query
if ($stmt->execute()) {
    // Redirect to admin page with success message
    header("Location: manageips.php?message=IP successfully whitelisted");
    exit();
} else {
    // Redirect to admin page with error message
    header("Location: manageips.php?message=Error whitelisting IP");
    exit();
}
?>
