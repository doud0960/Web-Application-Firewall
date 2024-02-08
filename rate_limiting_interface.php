<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rate Limiting Settings</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body {
            padding-top: 5rem;
        }
        .container {
            max-width: 600px;
        }
        .btn-primary {
            width: 100%;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2 class="mb-4">Rate Limiting Settings</h2>
        <form action="update_rate_limiting.php" method="post">
            <div class="form-group">
                <label for="max_requests">Max Requests:</label>
                <input type="number" id="max_requests" name="max_requests" value="<?php echo htmlspecialchars($max_requests); ?>" class="form-control">
            </div>
            <div class="form-group">
                <label for="time_period">Time Period (seconds):</label>
                <input type="number" id="time_period" name="time_period" value="<?php echo htmlspecialchars($time_period); ?>" class="form-control">
            </div>
            <button type="submit" class="btn btn-primary">Update Settings</button>
        </form>
    </div>
    <!-- Bootstrap JS and dependencies -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
