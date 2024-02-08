<?php
require_once 'db.php';
require_once 'functions.php';

$message = '';

// Check if the ID is provided and valid
if(isset($_GET['id']) && is_numeric($_GET['id'])) {
    $id = $_GET['id'];

    // Delete the user's data
    $query = "DELETE FROM users WHERE id = ?";
    if($stmt = mysqli_prepare($link, $query)) {
        mysqli_stmt_bind_param($stmt, "i", $id);
        if(mysqli_stmt_execute($stmt)) {
            $message = "User deleted successfully.";
        } else {
            $message = "Error deleting record: " . mysqli_error($link);
        }
        mysqli_stmt_close($stmt);
    }
} else {
    $message = "Invalid request.";
}

// Close the database connection
mysqli_close($link);

// Redirect to the user listing page with a message
header("Location: user_management.php?message=" . urlencode($message));
exit;
?>
