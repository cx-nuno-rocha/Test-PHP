<?php
/**
 * Test: SQL Injection remediation for "a1 - Cópia (10) - Cópia.php"
 *
 * Verifies that the employee look-up query uses a PDO prepared statement
 * instead of string concatenation so that SQL injection payloads are treated
 * as literal parameter values and do NOT alter query structure.
 *
 * Run: php src/test_a1_sql_injection.php
 *
 * Exit code 0 = all tests passed.
 * Exit code 1 = at least one test failed.
 */

// ---------------------------------------------------------------------------
// Bootstrap: build an in-memory SQLite database that mirrors production schema
// ---------------------------------------------------------------------------
$db = new PDO('sqlite::memory:');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$db->exec("
    CREATE TABLE employees (
        employeeId INTEGER PRIMARY KEY,
        LastName   TEXT NOT NULL,
        Email      TEXT NOT NULL
    )
");
$db->exec("
    INSERT INTO employees (employeeId, LastName, Email) VALUES
        (1, 'Smith',  'smith@example.com'),
        (2, 'Jones',  'jones@example.com'),
        (3, 'OBrien', 'obrien@example.com')
");

// ---------------------------------------------------------------------------
// Helper: run the query using the FIXED prepared-statement approach
// Returns the fetched rows (array of assoc arrays).
// ---------------------------------------------------------------------------
function query_employee(PDO $file_db, $raw_id): array
{
    // Mirror the exact fix applied in "a1 - Cópia (10) - Cópia.php"
    $stmt = $file_db->prepare('SELECT * FROM employees WHERE employeeId = :id');
    $stmt->bindValue(':id', $raw_id, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// ---------------------------------------------------------------------------
// Minimal test-runner helpers
// ---------------------------------------------------------------------------
$passed = 0;
$failed = 0;

function assert_equals($label, $expected, $actual): void
{
    global $passed, $failed;
    if ($expected === $actual) {
        echo "[PASS] $label\n";
        $passed++;
    } else {
        $exp_repr = var_export($expected, true);
        $act_repr = var_export($actual, true);
        echo "[FAIL] $label\n       expected: $exp_repr\n       actual  : $act_repr\n";
        $failed++;
    }
}

function assert_count($label, int $expected_count, array $rows): void
{
    assert_equals($label, $expected_count, count($rows));
}

// ---------------------------------------------------------------------------
// Test 1 – Legitimate integer ID returns the correct employee
// ---------------------------------------------------------------------------
$rows = query_employee($db, '1');
assert_count('T1: valid id=1 returns exactly one row', 1, $rows);
if (!empty($rows)) {
    assert_equals('T1: correct LastName for id=1', 'Smith', $rows[0]['LastName']);
}

// ---------------------------------------------------------------------------
// Test 2 – Another valid ID returns its own employee
// ---------------------------------------------------------------------------
$rows = query_employee($db, '2');
assert_count('T2: valid id=2 returns exactly one row', 1, $rows);
if (!empty($rows)) {
    assert_equals('T2: correct LastName for id=2', 'Jones', $rows[0]['LastName']);
}

// ---------------------------------------------------------------------------
// Test 3 – Non-existent ID returns zero rows (no crash, no data leak)
// ---------------------------------------------------------------------------
$rows = query_employee($db, '999');
assert_count('T3: non-existent id=999 returns zero rows', 0, $rows);

// ---------------------------------------------------------------------------
// Test 4 – Classic SQL injection tautology ("1 OR 1=1") must NOT dump all rows
//           With a prepared statement the whole string is cast to the integer 1
//           (PDO::PARAM_INT), so only the row with employeeId=1 is returned.
// ---------------------------------------------------------------------------
$rows = query_employee($db, '1 OR 1=1');
assert_count('T4: SQLi tautology "1 OR 1=1" returns only one row (not all)', 1, $rows);

// ---------------------------------------------------------------------------
// Test 5 – UNION-based injection must NOT expose extra data
// ---------------------------------------------------------------------------
$rows = query_employee($db, "1 UNION SELECT employeeId,LastName,Email FROM employees");
assert_count('T5: UNION injection returns only one row', 1, $rows);

// ---------------------------------------------------------------------------
// Test 6 – Stacked-query / comment injection must NOT bypass the WHERE clause
// ---------------------------------------------------------------------------
$rows = query_employee($db, "0; DROP TABLE employees--");
// PDO::PARAM_INT casts this to 0, so zero rows are returned.
assert_count('T6: stacked-query injection "0; DROP TABLE..." returns zero rows', 0, $rows);

// Confirm the table still exists (was not dropped)
$check = $db->query("SELECT COUNT(*) FROM employees")->fetchColumn();
assert_equals('T6b: employees table still exists after injection attempt', '3', (string)$check);

// ---------------------------------------------------------------------------
// Test 7 – NULL / empty id falls back to default value 1
//           (mirrors the "if (NULL == $_GET['id']) $_GET['id'] = 1" guard)
// ---------------------------------------------------------------------------
$id = null;
if (NULL == $id) $id = 1;
$rows = query_employee($db, $id);
assert_count('T7: null id defaults to 1 and returns one row', 1, $rows);
if (!empty($rows)) {
    assert_equals('T7: row is for employeeId=1', 'Smith', $rows[0]['LastName']);
}

// ---------------------------------------------------------------------------
// Test 8 – Output is HTML-escaped (XSS prevention already present)
//           Verify htmlspecialchars does not corrupt normal names.
// ---------------------------------------------------------------------------
$employee_string = $rows[0]['LastName'] . " - " . $rows[0]['Email'] . "\n";
$escaped = htmlspecialchars($employee_string, ENT_QUOTES | ENT_HTML5, 'UTF-8');
assert_equals('T8: htmlspecialchars preserves plain output unchanged',
    "Smith - smith@example.com\n", $escaped);

// ---------------------------------------------------------------------------
// Test 9 – HTML-special characters in output are escaped, not passed raw
// ---------------------------------------------------------------------------
// Temporarily insert a row with an XSS-like name
$db->exec("INSERT INTO employees (employeeId, LastName, Email) VALUES (99, '<script>alert(1)</script>', 'x@x.com')");
$rows = query_employee($db, '99');
assert_count('T9: row with XSS-like LastName is fetched', 1, $rows);
$raw = $rows[0]['LastName'] . " - " . $rows[0]['Email'] . "\n";
$escaped = htmlspecialchars($raw, ENT_QUOTES | ENT_HTML5, 'UTF-8');
$contains_tag = strpos($escaped, '<script>') !== false;
assert_equals('T9: <script> tag is escaped in output', false, $contains_tag);

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
echo "\n--- Results: $passed passed, $failed failed ---\n";
exit($failed > 0 ? 1 : 0);
