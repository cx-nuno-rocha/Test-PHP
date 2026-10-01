<?php

if (PHP_SAPI === 'cli') {
    parse_str(implode('&', array_slice($argv, 1)), $_GET);
}

$file_db = new PDO('sqlite:../database/database.sqlite');

if (NULL == $_GET['id']) $_GET['id'] = 1;

// Use a prepared statement with a bound parameter to prevent SQL injection / parameter tampering
$sql = 'SELECT * FROM employees WHERE employeeId = :id';
$stmt = $file_db->prepare($sql);
$stmt->bindValue(':id', $_GET['id'], PDO::PARAM_INT);
$stmt->execute();

foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
    $employee = $row['LastName'] . " - " . $row['Email'] . "\n";

    echo htmlspecialchars($employee, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}
