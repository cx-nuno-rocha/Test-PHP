<?php

// Enforce HTTPS by sending HTTP Strict Transport Security header (HSTS)
// This prevents protocol downgrade attacks and cookie hijacking over HTTP
if (PHP_SAPI !== 'cli') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

if (PHP_SAPI === 'cli') {
    parse_str(implode('&', array_slice($argv, 1)), $_GET);
}

$file_db = new PDO('sqlite:../database/database.sqlite');

if (NULL == $_GET['id']) $_GET['id'] = 1;

$sql = 'SELECT * FROM employees WHERE employeeId = ' . $_GET['id'];

foreach ($file_db->query($sql) as $row) {
    $employee = $row['LastName'] . " - " . $row['Email'] . "\n";

    echo htmlspecialchars($employee, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}
