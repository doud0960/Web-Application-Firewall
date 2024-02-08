<?php
require_once 'db.php';
require_once 'functions.php';

// Get the full URL
$url = $_SERVER['REQUEST_URI'];



//rate_limting DDoS
$user_ip = $_SERVER['REMOTE_ADDR'];
rate_limiting($user_ip);


// Query to fetch attack logs
$query_logs = "SELECT attack_type, user_ip, timestamp FROM attack_logs ORDER BY timestamp DESC";
$result_logs = mysqli_query($link, $query_logs);
// PHP code to fetch daily statistics for analytics and trends
$query_daily_stats = "SELECT total_requests, total_attacks, total_blocks, date FROM daily_stats ORDER BY date DESC LIMIT 7";
$result_daily_stats = mysqli_query($link, $query_daily_stats);

$daily_stats_data = array();
while ($row = mysqli_fetch_assoc($result_daily_stats)) {
    $daily_stats_data[] = $row;
}


// Query to fetch attack logs
$query_logs = "SELECT attack_type, user_ip, timestamp FROM attack_logs ORDER BY timestamp DESC";
$result_logs = mysqli_query($link, $query_logs);

// Query to fetch attack overview (counts of various types of attacks)
$query_overview = "SELECT attack_type, COUNT(*) as count FROM attack_logs GROUP BY attack_type";
$result_overview = mysqli_query($link, $query_overview);

// Placeholder for alert area (can be implemented based on specific requirements)
$alert_message = "Recent attacks detected! Check logs.";

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Admin Dashboard</title>
    <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        .section-heading {
            margin-top: 30px;
            margin-bottom: 20px;
            
        }
        .alert-area {
            margin-bottom: 20px;

        }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="text-center my-4">Monitoring Dashboard</h1>
        
        <!-- Alert Area for Attack Notifications -->
        <div class="alert-area">
            <div class="alert alert-warning"><?= $alert_message ?></div>
        </div>
        
        <!-- Overview of Attacks -->
        <h3 class="section-heading">Overview of Attacks</h3>
        <div class="row">
            <?php while ($row = mysqli_fetch_assoc($result_overview)) { ?>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title"><?= $row['attack_type'] ?></h5>
                            <p class="card-text">Count: <?= $row['count'] ?></p>
                        </div>
                    </div>
                </div>
            <?php } ?>
        </div>

        <!-- Attack Logs -->
        <h3 class="section-heading">Attack Logs</h3>
        <div class="row">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Attack Type</th>
                        <th>User IP</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($row = mysqli_fetch_assoc($result_logs)) { ?>
                        <tr>
                            <td><?= $row['attack_type'] ?></td>
                            <td><?= $row['user_ip'] ?></td>
                            <td><?= $row['timestamp'] ?></td>
                        </tr>
                    <?php } ?>
                </tbody>
            </table>
    </div>

        <canvas id="dailyStatsChart" width="350" height="150"></canvas>
        
        <a href="system_health.php" class="btn btn-primary">System Health</a>
        <a href="user_management.php" class="btn btn-primary">User Management</a>
        <a href="file_upload.php" class="btn btn-primary">File Uploads Interface</a>
        <a href="rules_management.php" class="btn btn-primary">Manage Rules</a>
        <a href="manageips.php" class="btn btn-primary">Manage IPs</a>
        <a href="rate_limiting_interface.php" class="btn btn-primary">Rate Limit</a>
    <script>
    var ctx = document.getElementById('dailyStatsChart').getContext('2d');
    var myChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [
                <?php
                    foreach ($daily_stats_data as $day) {
                        echo '"' . $day['date'] . '", ';
                    }
                ?>
            ],
            datasets: [{
                label: 'Total Requests',
                data: [
                    <?php
                        foreach ($daily_stats_data as $day) {
                            echo $day['total_requests'] . ', ';
                        }
                    ?>
                ],
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 3
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
</script>
<!--logout -->

<!-- Logout Button -->
<div class="container mt-4">
  <a href="logout.php" class="btn btn-danger">Logout</a>
</div>


</body>
</html>






    

    
   

