<?php
// Include your functions.php file and database connection
require_once 'db.php';
require_once 'functions.php';

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['id'])) {
    // Fetch the rule to edit
    $id = $_GET['id'];
    $rule = getRule($link, $id);
    if (!$rule) {
        die("Rule not found.");
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['updateRule'])) {
    // Process the form submission for updating the rule
    $id = $_POST['id'];
    $name = $_POST['name'];
    $type = $_POST['type'];
    $pattern = $_POST['pattern'];
    $action = $_POST['action'];
    $status = $_POST['status'];

    updateRule($link, $id, $name, $type, $pattern, $action, $status);
    header('Location: rules_management.php');
    exit;
} else {
    die("Invalid request.");
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit WAF Rule</title>
    <!-- Include Bootstrap CSS from CDN -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-4">
        <div class="card">
            <div class="card-header">
                Edit Rule
            </div>
            <div class="card-body">
                <form action="edit_rule.php" method="post">
                    <input type="hidden" name="id" value="<?php echo htmlspecialchars($rule['id']); ?>">
                    
                    <div class="form-group">
                        <label for="name">Rule Name:</label>
                        <input type="text" class="form-control" id="name" name="name" value="<?php echo htmlspecialchars($rule['name']); ?>" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="type">Rule Type:</label>
                        <input type="text" class="form-control" id="type" name="type" value="<?php echo htmlspecialchars($rule['type']); ?>" required>
                    </div>

                    <div class="form-group">
                        <label for="pattern">Pattern:</label>
                        <textarea class="form-control" id="pattern" name="pattern" required><?php echo htmlspecialchars($rule['pattern']); ?></textarea>
                    </div>

                    <div class="form-group">
                        <label for="action">Action:</label>
                        <select class="form-control" id="action" name="action">
                            <option value="block" <?php echo $rule['action'] == 'block' ? 'selected' : ''; ?>>Block</option>
                            <option value="allow" <?php echo $rule['action'] == 'allow' ? 'selected' : ''; ?>>Allow</option>
                            <option value="log" <?php echo $rule['action'] == 'log' ? 'selected' : ''; ?>>Log</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="status">Status:</label>
                        <select class="form-control" id="status" name="status">
                            <option value="active" <?php echo $rule['status'] == 'active' ? 'selected' : ''; ?>>Active</option>
                            <option value="inactive" <?php echo $rule['status'] == 'inactive' ? 'selected' : ''; ?>>Inactive</option>
                        </select>
                    </div>

                    <button type="submit" name="updateRule" class="btn btn-primary">Update Rule</button>
                </form>
            </div>
        </div>
    </div>

    <!-- Include Bootstrap JS and its dependencies (jQuery and Popper) -->
    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
</body>
</html>
