<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>System Health</title>
  <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

  <script>


    // Function to auto-refresh the system health data every 2 seconds (5000 milliseconds)
    function refreshData() {
      location.reload();
    }
    setInterval(refreshData, 2000);
  </script>

    <style>
    #systemHealthChart {
        max-width: 600px;
        margin: 0 auto;
    }
    </style>


</head>
<body>
  <div class="container mt-5">
    <h1 class="text-center">System Health Dashboard</h1>
    <div class="card mt-5">
      <div class="card-body">
        <h5 class="card-title">System Statistics</h5>
        <p class="card-text">
          
          

          
<?php
          // Function to get server load (CPU usage)
          function get_server_load() {
              $load = sys_getloadavg();
              return $load[0];
          }
          // Function to get server memory usage
          function get_server_memory_usage() {
              $free = shell_exec('free');
              $free = (string)trim($free);
              $free_arr = explode("\n", $free);
              $mem = explode(" ", $free_arr[1]);
              $mem = array_filter($mem);
              $mem = array_merge($mem);
              $memory_usage = $mem[2] / $mem[1] * 100;
              return $memory_usage;
          }
          // Disk space
          $free_space = disk_free_space("/");
          $total_space = disk_total_space("/");
          // Uptime
          $uptime = shell_exec("uptime -p");
          ?>
          <strong>CPU Usage:</strong> <?php echo get_server_load(); ?>% <br>
          <strong>Memory Usage:</strong> <?php echo get_server_memory_usage(); ?>% <br>
          <strong>Disk Space:</strong> Free: <?php echo $free_space; ?> / Total: <?php echo $total_space; ?> <br>
          <strong>Uptime:</strong> <?php echo $uptime; ?>
        </p>
      </div>
    </div>
  </div>

  <canvas id="systemHealthChart" width="400" height="400"></canvas>


  <div class="chart-container" style="position: relative; height:40vh; width:80vw">
    <canvas id="cpuChart"></canvas>
</div>
<div class="chart-container" style="position: relative; height:40vh; width:80vw">
    <canvas id="memoryChart"></canvas>
</div>




</body>
</html>
