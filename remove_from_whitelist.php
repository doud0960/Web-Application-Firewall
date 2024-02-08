<?php
require_once "db.php";

// Check if the id is present
if (isset($_GET['id'])) {
    $ip_to_remove = $_GET['id'];
    $query = "DELETE FROM whitelist WHERE id = ?";
    $stmt = $link->prepare($query);
    $stmt->bind_param("i", $ip_to_remove);

    if ($stmt->execute()) {
        header("Location: manageips.php?message=IP successfully removed from whitelist");
    } else {
        header("Location: manageips.php?message=Error removing IP from whitelist");
    }
    $stmt->close();
    $link->close();
} else {
    header("Location: manageips.php?message=Invalid request");
}
?>
