<?php
// Include your functions.php file and database connection
require_once 'db.php';
require_once 'functions.php';

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['id'])) {
    $id = $_GET['id'];
    deleteRule($link, $id);
}

// Redirect to the rules management page after deletion
header('Location: rules_management.php');
exit;
?>
