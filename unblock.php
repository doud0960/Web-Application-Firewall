<?php
require_once 'db.php';

// Check if the id is set and not empty
if (isset($_GET['id']) && !empty($_GET['id'])) {
    $id_to_unblock = $_GET['id'];

    // Prepare an SQL query to delete the IP from the blacklist table using the ID
    $query = "DELETE FROM blacklist WHERE id = ?";
    $stmt = $link->prepare($query);
    $stmt->bind_param("i", $id_to_unblock);

    if ($stmt->execute()) {
        // Redirect to manageips.php with success message
        header("Location: manageips.php?message=IP successfully unblocked");
    } else {
        // Redirect to manageips.php with error message
        header("Location: manageips.php?message=Error unblocking IP");
    }
    
    $stmt->close();
    $link->close();
} else {
    // Redirect to manageips.php with error message if the ID is not set
    header("Location: manageips.php?message=Invalid request");
}
?>
