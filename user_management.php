
<?php
// Database connection
require_once 'db.php';
require_once 'functions.php';

// Add new users
// Add new users
// Add new users
if (isset($_POST['add_user'])) {
    $username = isset($_POST['username']) ? mysqli_real_escape_string($link, $_POST['username']) : '';
    $email = isset($_POST['email']) ? mysqli_real_escape_string($link, $_POST['email']) : '';
    $password = isset($_POST['password']) ? password_hash($_POST['password'], PASSWORD_DEFAULT) : ''; // Never store plain passwords
    $role = isset($_POST['role']) ? mysqli_real_escape_string($link, $_POST['role']) : '';

    // Check if username already exists
    $query = "SELECT id FROM users WHERE username = ?";
    if ($check_stmt = mysqli_prepare($link, $query)) {
        mysqli_stmt_bind_param($check_stmt, "s", $username);
        if (mysqli_stmt_execute($check_stmt)) {
            mysqli_stmt_store_result($check_stmt);
            if (mysqli_stmt_num_rows($check_stmt) == 0) {
                // Username doesn't exist, proceed with insert
                $sql = "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)";
                if ($insert_stmt = mysqli_prepare($link, $sql)) {
                    mysqli_stmt_bind_param($insert_stmt, "ssss", $username, $email, $password, $role);
                    if (mysqli_stmt_execute($insert_stmt)) {
                        echo "User added successfully.";
                    } else {
                        echo "Error: " . $sql . "<br>" . mysqli_error($link);
                    }
                    mysqli_stmt_close($insert_stmt);
                }
            } else {
                echo "Username already exists.";
            }
        } else {
            echo "Error checking username: " . mysqli_error($link);
        }
        mysqli_stmt_close($check_stmt);
    }
}



// Update (Modify existing user details)
if (isset($_POST['update_user'])) {
    $user_id = isset($_POST['id']) ? $_POST['id'] : 0;
    $username = isset($_POST['username']) ? mysqli_real_escape_string($link, $_POST['username']) : '';
    $email = isset($_POST['email']) ? mysqli_real_escape_string($link, $_POST['email']) : '';
    $role = isset($_POST['role']) ? mysqli_real_escape_string($link, $_POST['role']) : '';

    $sql = "UPDATE users SET username=?, email=?, role=? WHERE id=?";
    if($stmt = mysqli_prepare($link, $sql)){
        mysqli_stmt_bind_param($stmt, "sssi", $username, $email, $role, $user_id);
        if(mysqli_stmt_execute($stmt)){
            echo "User updated successfully.";
        } else {
            echo "Error: " . $sql . "<br>" . mysqli_error($link);
        }
        mysqli_stmt_close($stmt);
    }
}

// Delete users
if (isset($_POST['delete_user'])) {
    $user_id = isset($_POST['id']) ? $_POST['id'] : 0;
    $sql = "DELETE FROM users WHERE id = ?";
    if($stmt = mysqli_prepare($link, $sql)){
        mysqli_stmt_bind_param($stmt, "i", $user_id);
        if(mysqli_stmt_execute($stmt)){
            echo "User deleted successfully.";
        } else {
            echo "Error: " . $sql . "<br>" . mysqli_error($link);
        }
        mysqli_stmt_close($stmt);
    }
}



function list_users($link) {
    // Begin the table
    echo '<table class="table table-bordered">';
    echo '<thead>';
    echo '<tr>';
    echo '<th>ID</th>';
    echo '<th>Username</th>';
    echo '<th>Email</th>';
    echo '<th>Role</th>';
    echo '<th>Actions</th>';
    echo '</tr>';
    echo '</thead>';
    echo '<tbody>';

    // SQL query to select data from the database
    $sql = "SELECT id, username, email, role FROM users";
    $result = mysqli_query($link, $sql);

    // Check if there are any results and output each row
    if (mysqli_num_rows($result) > 0) {
        while($row = mysqli_fetch_assoc($result)) {
            echo '<tr>';
            echo '<td>' . htmlspecialchars($row["id"]) . '</td>';
            echo '<td>' . htmlspecialchars($row["username"]) . '</td>';
            echo '<td>' . htmlspecialchars($row["email"]) . '</td>';
            echo '<td>' . htmlspecialchars($row["role"]) . '</td>';
            echo '<td>';
            // Add buttons or links for edit and delete actions here
            echo '<a href="edit_user.php?id=' . htmlspecialchars($row["id"]) . '" class="btn btn-primary btn-sm">Edit</a> ';
            echo '<a href="delete_user.php?id=' . htmlspecialchars($row["id"]) . '" class="btn btn-danger btn-sm" onclick="return confirm(\'Are you sure you want to delete this user?\')">Delete</a>';
            echo '</td>';
            echo '</tr>';
        }
    } else {
        echo '<tr><td colspan="5">No users found.</td></tr>';
    }

    // End the table
    echo '</tbody>';
    echo '</table>';
}




// Include your HTML and frontend UI here





;
?>

<!-- HTML and Bootstrap for frontend UI -->
<!DOCTYPE html>
<html>
<head>
    <title>User Management</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <script>
        function deleteUser(id) {
            if (confirm('Are you sure you want to delete this user?')) {
                // Add AJAX call here to delete the user
            }
        }
    </script>
</head>
<body>
    <div class="container mt-5">
        <h1>User Management</h1>
        
        <!-- Add User Form -->
        <h2>Add New User</h2>
        <form action="" method="post">
            <div class="form-group">
                <input type="text" class="form-control" name="username" placeholder="Username">
            </div>
            <div class="form-group">
                <input type="email" class="form-control" name="email" placeholder="Email">
            </div>
            <div class="form-group">
                <input type="password" class="form-control" name="password" placeholder="Password">
            </div>
            <div class="form-group">
                <select class="form-control" name="role">
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                </select>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" name="add_user" value="Add User">
            </div>
        </form>

        
        <!-- List Users -->
        <h2>Existing Users</h2>
        <?php list_users($link); ?>
    </div>
</body>
</html>
