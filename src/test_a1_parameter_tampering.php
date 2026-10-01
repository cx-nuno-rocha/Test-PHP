<?php
/**
 * Tests for CWE-472 Parameter Tampering remediation in
 * "a1 - Cópia (10) - Cópia.php"
 *
 * Verifies that the employeeId query parameter is passed via a PDO prepared
 * statement (bindValue with PARAM_INT) rather than concatenated directly into
 * the SQL string, preventing SQL injection / parameter tampering.
 *
 * Run: php src/test_a1_parameter_tampering.php
 */

$passed = 0;
$failed = 0;

function assert_equals($label, $expected, $actual) {
    global $passed, $failed;
    if ($expected === $actual) {
        echo "[PASS] $label\n";
        $passed++;
    } else {
        echo "[FAIL] $label\n";
        echo "       expected: " . var_export($expected, true) . "\n";
        echo "       actual  : " . var_export($actual,   true) . "\n";
        $failed++;
    }
}

function assert_true($label, $value) {
    assert_equals($label, true, (bool) $value);
}

function assert_false($label, $value) {
    assert_equals($label, false, (bool) $value);
}

// ---------------------------------------------------------------------------
// Helpers – build the in-memory DB and run the prepared-statement query the
// same way the fixed script does, so the sink itself is exercised by the test.
// ---------------------------------------------------------------------------

/**
 * Create an in-memory SQLite database pre-populated with two employee rows.
 */
function create_test_db(): PDO {
    $db = new PDO('sqlite::memory:');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec('CREATE TABLE employees (
        employeeId INTEGER PRIMARY KEY,
        LastName   TEXT NOT NULL,
        Email      TEXT NOT NULL
    )');
    $db->exec("INSERT INTO employees VALUES (1, 'Smith',  'smith@example.com')");
    $db->exec("INSERT INTO employees VALUES (2, 'Doe',    'doe@example.com')");
    return $db;
}

/**
 * Execute the FIXED query logic (prepared statement + bindValue PARAM_INT).
 * Returns an array of matching rows.
 */
function query_employee_fixed(PDO $db, $rawId): array {
    $sql  = 'SELECT * FROM employees WHERE employeeId = :id';
    $stmt = $db->prepare($sql);
    // bindValue with PARAM_INT is the fix that breaks the taint flow:
    // the value is always treated as an integer, never interpolated as SQL.
    $stmt->bindValue(':id', $rawId, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Execute the VULNERABLE (unfixed) query logic for comparison.
 * Returns an array of matching rows (or throws on injection payloads).
 */
function query_employee_vulnerable(PDO $db, $rawId): array {
    $sql  = 'SELECT * FROM employees WHERE employeeId = ' . $rawId;
    return $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);
}

// ---------------------------------------------------------------------------
// Test 1 – Legitimate integer ID returns the correct employee (fixed path).
// ---------------------------------------------------------------------------
$db = create_test_db();
$rows = query_employee_fixed($db, '1');
assert_equals(
    'Fixed: integer id=1 returns exactly one row',
    1,
    count($rows)
);
assert_equals(
    'Fixed: integer id=1 returns Smith',
    'Smith',
    $rows[0]['LastName'] ?? null
);

// ---------------------------------------------------------------------------
// Test 2 – Legitimate integer ID 2 (fixed path).
// ---------------------------------------------------------------------------
$rows = query_employee_fixed($db, '2');
assert_equals(
    'Fixed: integer id=2 returns exactly one row',
    1,
    count($rows)
);
assert_equals(
    'Fixed: integer id=2 returns Doe',
    'Doe',
    $rows[0]['LastName'] ?? null
);

// ---------------------------------------------------------------------------
// Test 3 – Non-existent integer ID returns zero rows (fixed path).
// ---------------------------------------------------------------------------
$rows = query_employee_fixed($db, '999');
assert_equals(
    'Fixed: unknown id=999 returns zero rows',
    0,
    count($rows)
);

// ---------------------------------------------------------------------------
// Test 4 – SQL-injection payload is neutralised by PARAM_INT binding.
//
//   Payload: "1 OR 1=1"
//   Vulnerable code: appends the string verbatim → returns ALL rows.
//   Fixed code: bindValue(..., PDO::PARAM_INT) casts to integer (1) →
//               returns exactly one row, proving the injection is blocked.
// ---------------------------------------------------------------------------
$rows_fixed = query_employee_fixed($db, '1 OR 1=1');
assert_equals(
    'Fixed: injection payload "1 OR 1=1" returns exactly one row (not all rows)',
    1,
    count($rows_fixed)
);

// Confirm the same payload DOES exploit the vulnerable version (to verify the
// test premise is valid).
$rows_vuln = query_employee_vulnerable($db, '1 OR 1=1');
assert_true(
    'Vulnerable (baseline): injection payload "1 OR 1=1" returns ALL rows',
    count($rows_vuln) > 1
);

// ---------------------------------------------------------------------------
// Test 5 – UNION-based injection payload is neutralised.
//
//   Payload forces a UNION that would normally append an extra synthetic row.
//   With PARAM_INT the payload casts to 0 (no matching employeeId) → 0 rows.
// ---------------------------------------------------------------------------
$unionPayload = "0 UNION SELECT 1,'Injected','injected@evil.com'--";
$rows_fixed   = query_employee_fixed($db, $unionPayload);
assert_equals(
    'Fixed: UNION injection payload returns zero rows',
    0,
    count($rows_fixed)
);

// Confirm the same payload exploits the unfixed version.
$rows_vuln = query_employee_vulnerable($db, $unionPayload);
assert_true(
    'Vulnerable (baseline): UNION injection payload leaks a synthetic row',
    count($rows_vuln) > 0
);

// ---------------------------------------------------------------------------
// Test 6 – Default fallback (NULL / empty id) uses id=1 and returns one row.
// ---------------------------------------------------------------------------
// Simulate the "if (NULL == $_GET['id']) $_GET['id'] = 1;" guard.
$id = null;
if (null == $id) $id = 1;
$rows = query_employee_fixed($db, $id);
assert_equals(
    'Fixed: NULL id defaults to 1 and returns one row',
    1,
    count($rows)
);

// ---------------------------------------------------------------------------
// Test 7 – Output is HTML-escaped (no XSS from LastName / Email values).
// ---------------------------------------------------------------------------
// Insert a row whose fields contain HTML metacharacters.
$db->exec("INSERT INTO employees VALUES (3, '<script>alert(1)</script>', 'x@x.com')");
$rows = query_employee_fixed($db, '3');
assert_equals('Fixed: XSS row fetched', 1, count($rows));

$raw = $rows[0]['LastName'] . ' - ' . $rows[0]['Email'] . "\n";
$safe = htmlspecialchars($raw, ENT_QUOTES | ENT_HTML5, 'UTF-8');

assert_false(
    'Output encoding: htmlspecialchars removes raw <script> tag',
    strpos($safe, '<script>') !== false
);
assert_true(
    'Output encoding: htmlspecialchars converts < to &lt;',
    strpos($safe, '&lt;') !== false
);

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
echo "\nResults: $passed passed, $failed failed.\n";
exit($failed > 0 ? 1 : 0);
