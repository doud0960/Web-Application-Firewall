<?php
// Include database connection
require_once 'db.php';

// Get the settings from POST data
$max_requests = $_POST['max_requests'];
$time_period = $_POST['time_period'];

// Prepare the update query
$query = "UPDATE rate_limiting_settings SET max_requests = ?, time_period = ? WHERE id = 1";
$stmt = $link->prepare($query);
$stmt->bind_param("ii", $max_requests, $time_period);

// Execute the query
if ($stmt->execute()) {
    // Redirect back with a success message
    header("Location: admin.php?message=Settings updated successfully");
} else {
    // Redirect back with an error message
    header("Location: rate_limiting_interface.php?message=Error updating settings");
}

$stmt->close();
$link->close();
?>
