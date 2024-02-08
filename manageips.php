<?php

require_once 'db.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Management</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            padding-top: 5rem;
        }
        .container {
            padding-bottom: 100px; /* Footer height */
        }
        .table {
            margin-top: 20px;
        }
        footer {
            position: absolute;
            bottom: 0;
            width: 100%;
            height: 60px;
            line-height: 60px; /* Vertically center the text there */
            background-color: #f5f5f5;
        }
        .footer-text {
            margin: 0;
            text-align: center;
        }
    </style>
</head>
<body>

<nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
    <a class="navbar-brand" href="#">WAF Dashboard</a>
    <div class="collapse navbar-collapse">
        <ul class="navbar-nav mr-auto">
            <li class="nav-item">
                <a class="nav-link" href="admin.php">Dashboard</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="rule_management.php">Rule Management</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="user_management.php">User Management</a>
            </li>
            <li class="nav-item active">
                <a class="nav-link" href="manageips.php">Manage IPs</a>
            </li>
        </ul>
    </div>
</nav>

<div class="container">
    <!-- Whitelist Section -->
    <!-- Whitelist Section -->
    <section class="mt-4">
        <h2>Whitelist IPs</h2>
        <form action="whitelist.php" method="post" class="form-inline mb-2">
            <input type="text" name="ip" class="form-control mr-2" placeholder="Enter IP to whitelist">
            <button type="submit" class="btn btn-primary">Whitelist IP</button>
        </form>
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php
                // Fetch whitelist IPs
                $whitelist_query = "SELECT id, ip_address FROM whitelist";
                $whitelist_result = mysqli_query($link, $whitelist_query);
                while($row = mysqli_fetch_assoc($whitelist_result)): ?>
                <tr>
                    <td><?php echo htmlspecialchars($row['ip_address']); ?></td>
                    <td><a href="remove_from_whitelist.php?id=<?php echo $row['id']; ?>" class="btn btn-danger btn-sm" onclick="return confirm('Are you sure you want to remove this IP?');">Remove</a></td>
                </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </section>>

    
        <!-- Blacklist Section -->
        <section class="mt-4">
            <h2>Blacklist IPs</h2>
            <form action="blacklist.php" method="post" class="form-inline mb-2">
                <input type="text" name="ip" class="form-control mr-2" placeholder="Enter IP to blacklist">
                <button type="submit" class="btn btn-danger">Blacklist IP</button>
            </form>
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    // Fetch blacklist IPs
                    $blacklist_query = "SELECT id, ip_address FROM blacklist";
                    $blacklist_result = mysqli_query($link, $blacklist_query);
                    while($row = mysqli_fetch_assoc($blacklist_result)): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($row['ip_address']); ?></td>
                        <td><a href="unblock.php?id=<?php echo $row['id']; ?>" class="btn btn-warning btn-sm">Remove</a></td>

                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </section>
</div>



<script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
