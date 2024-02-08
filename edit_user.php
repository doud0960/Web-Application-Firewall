<?php
require_once 'db.php';
require_once 'functions.php';

// Initialize variables
$user = [
    'id' => '',
    'username' => '',
    'email' => '',
    'role' => ''
];
$update_success = false;
$errors = [];

// Check if the ID is provided and valid
if(isset($_GET['id']) && is_numeric($_GET['id'])) {
    $id = $_GET['id'];

    // Fetch the user's data
    $query = "SELECT id, username, email, role FROM users WHERE id = ?";
    if($stmt = mysqli_prepare($link, $query)) {
        mysqli_stmt_bind_param($stmt, "i", $id);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        $user = mysqli_fetch_assoc($result);
        mysqli_stmt_close($stmt);
    }
}

// Process the form when submitted
if($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['update_user'])) {
    // Validate and sanitize input
    $user['id'] = $_POST['id'];
    $user['username'] = sanitize_input($_POST['username']);
    $user['email'] = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $user['role'] = sanitize_input($_POST['role']);

    // Update the user in the database
    $query = "UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?";
    if($stmt = mysqli_prepare($link, $query)) {
        mysqli_stmt_bind_param($stmt, "sssi", $user['username'], $user['email'], $user['role'], $user['id']);
        if(mysqli_stmt_execute($stmt)) {
            $update_success = true;
        } else {
            $errors[] = "Error updating record: " . mysqli_error($link);
        }
        mysqli_stmt_close($stmt);
    }
}

// Close the database connection
mysqli_close($link);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Edit User</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .container {
            margin-top: 50px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        .error {
            color: red;
        }
        .success {
            color: green;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Edit User</h2>
        <?php if($update_success): ?>
            <p class="success">User updated successfully.</p>
        <?php endif; ?>
        <?php foreach($errors as $error): ?>
            <p class="error"><?php echo $error; ?></p>
        <?php endforeach; ?>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]) . '?id=' . $user['id']; ?>" method="post">
            <input type="hidden" name="id" value="<?php echo $user['id']; ?>">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" name="username" class="form-control" value="<?php echo $user['username']; ?>" required>
            </div>
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" name="email" class="form-control" value="<?php echo $user['email']; ?>" required>
            </div>
            <div class="form-group">
                <label for="role">Role:</label>
                <select name="role" class="form-control">
                    <option value="user" <?php echo $user['role'] === 'user' ? 'selected' : ''; ?>>User</option>
                    <option value="admin" <?php echo $user['role'] === 'admin' ? 'selected' : ''; ?>>Admin</option>
                </select>
            </div>
            <button type="submit" class="btn btn-primary" name="update_user">Update User</button>
        </form>
    </div>

    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
</body>
</html>
