<?php
require_once 'db.php'; // Include the database connection

// Function to fetch rules from the database
function getRules($link) {
    $result = $link->query("SELECT * FROM waf_rules");
    return $result->fetch_all(MYSQLI_ASSOC);
}

// Check if the form was submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['createRule'])) {
    // Retrieve form data
    $name = $_POST['name'];
    $type = $_POST['type'];
    $pattern = $_POST['pattern'];
    $action = $_POST['action'];
    $status = $_POST['status'];

    // Prepare the SQL statement with placeholders
    $stmt = $link->prepare("INSERT INTO waf_rules (name, type, pattern, action, status) VALUES (?, ?, ?, ?, ?)");
    
    // Bind the variables to the statement as parameters
    $stmt->bind_param("sssss", $name, $type, $pattern, $action, $status);

    // Execute the statement and check for errors
    if ($stmt->execute()) {
        echo "<p class='alert alert-success'>New rule created successfully.</p>";
    } else {
        echo "<p class='alert alert-danger'>Error: " . $stmt->error . "</p>";
    }

    // Close the statement
    $stmt->close();
}

// Fetch rules for display in the table
$rules = getRules($link);
?>




<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Rule Management</title>
    <!-- Include Bootstrap CSS from CDN -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-4">
        <!-- Create Rule Form -->
        <div class="card mb-4">
            <div class="card-header">Create New Rule</div>
            <div class="card-body">
                <form action="rules_management.php" method="post">
                    <div class="form-group">
                        <label for="name">Rule Name:</label>
                        <input type="text" class="form-control" id="name" name="name" required>
                    </div>
                    <div class="form-group">
                        <label for="type">Rule Type:</label>
                        <input type="text" class="form-control" id="type" name="type" required>
                    </div>
                    <div class="form-group">
                        <label for="pattern">Pattern:</label>
                        <textarea class="form-control" id="pattern" name="pattern" required></textarea>
                    </div>
                    <div class="form-group">
                        <label for="action">Action:</label>
                        <select class="form-control" id="action" name="action">
                            <option value="block">Block</option>
                            <option value="allow">Allow</option>
                            <option value="log">Log</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="status">Status:</label>
                        <select class="form-control" id="status" name="status">
                            <option value="active">Active</option>
                            <option value="inactive">Inactive</option>
                        </select>
                    </div>
                    <button type="submit" name="createRule" class="btn btn-primary">Create Rule</button>
                </form>
            </div>
        </div>

        <!-- Existing Rules Table -->
        <div class="card">
            <div class="card-header">Existing Rules</div>
            <div class="card-body">
                <table class="table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Name</th>
                            <th>Type</th>
                            <th>Pattern</th>
                            <th>Action</th>
                            <th>Status</th>
                            <th>Operations</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- PHP code to loop through rules and create table rows -->
                        <?php
                    
                        // Assuming $link is your database connection
                        $rules = getRules($link);
                        foreach ($rules as $rule) {
                            echo "<tr>";
                            echo "<td>" . htmlspecialchars($rule['id']) . "</td>";
                            echo "<td>" . htmlspecialchars($rule['name']) . "</td>";
                            echo "<td>" . htmlspecialchars($rule['type']) . "</td>";
                            echo "<td>" . htmlspecialchars($rule['pattern']) . "</td>";
                            echo "<td>" . htmlspecialchars($rule['action']) . "</td>";
                            echo "<td>" . htmlspecialchars($rule['status']) . "</td>";
                            echo "<td>
                                    <a href='edit_rule.php?id=" . urlencode($rule['id']) . "' class='btn btn-sm btn-warning'>Edit</a>
                                    <a href='delete_rule.php?id=" . urlencode($rule['id']) . "' class='btn btn-sm btn-danger' onclick='return confirm(\"Are you sure you want to delete this rule?\")'>Delete</a>
                                  </td>";
                            echo "</tr>";
                        }
                        ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Include Bootstrap JS and its dependencies (jQuery and Popper) -->
    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
</body>
</html>
