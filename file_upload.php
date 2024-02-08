<!DOCTYPE html>
<html>
<head>
    <title>File Upload</title>
    <!-- Include Bootstrap CSS -->
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>

<div class="container mt-5">
    <h1 class="text-center">File Upload Form</h1>

    <form action="" method="post" enctype="multipart/form-data" class="mt-4">
        <div class="form-group">
            <label for="uploaded_file">Select file to upload:</label>
            <input type="file" class="form-control-file" name="uploaded_file" id="uploaded_file">
        </div>
        <button type="submit" class="btn btn-primary">Upload File</button>
    </form>

    <?php
    include 'functions.php';  // Include your functions.php file to access the handle_file_upload function

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_FILES['uploaded_file'])) {
            $result = handle_file_upload($_FILES['uploaded_file']);
            echo "<div class='alert alert-info mt-4'>$result</div>";
        }
    }
    ?>
</div>

<!-- Include Bootstrap JS (optional) -->
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>

</body>
</html>
