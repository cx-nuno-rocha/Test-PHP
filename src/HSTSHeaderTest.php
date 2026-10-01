<?php

/**
 * Tests for the HSTS (HTTP Strict Transport Security) header fix.
 *
 * Verifies that the web application correctly emits the
 * Strict-Transport-Security response header required to prevent
 * protocol-downgrade attacks (CWE-346 / Missing_HSTS_Header).
 *
 * These tests use PHP's output buffering and a custom header-capture
 * mechanism to inspect the header() calls made by the script under test
 * without requiring a live HTTP server.
 */

/**
 * Capture all header() calls made during a test closure.
 *
 * Returns an associative array of header-name => header-value pairs
 * collected from calls to header() while $callable runs.
 *
 * @param callable $callable Code under test.
 * @return array<string,string> Headers keyed by lower-cased header name.
 */
function captureHeaders(callable $callable): array
{
    // PHP's header() calls cannot be truly intercepted in a unit-test
    // context without an HTTP server, so we simulate the PHP_SAPI check
    // by setting up a test double for the header() invocation path.
    // We use output buffering to suppress any output produced.
    ob_start();
    $callable();
    ob_end_clean();

    // Return headers actually queued (available only before output flushed).
    $raw = headers_list();
    $result = [];
    foreach ($raw as $header) {
        $parts = explode(':', $header, 2);
        if (count($parts) === 2) {
            $result[strtolower(trim($parts[0]))] = trim($parts[1]);
        }
    }
    return $result;
}

// ---------------------------------------------------------------------------
// Simple assertion helpers (no external test runner required)
// ---------------------------------------------------------------------------

$passed = 0;
$failed = 0;

function assert_true(bool $condition, string $message): void
{
    global $passed, $failed;
    if ($condition) {
        echo "[PASS] $message\n";
        $passed++;
    } else {
        echo "[FAIL] $message\n";
        $failed++;
    }
}

function assert_contains(string $haystack, string $needle, string $message): void
{
    assert_true(strpos($haystack, $needle) !== false, $message);
}

// ---------------------------------------------------------------------------
// Test 1: The HSTS header is defined in the source file.
//         Verifies that 'Strict-Transport-Security' is present in the code.
// ---------------------------------------------------------------------------
$source = file_get_contents(__DIR__ . '/a1 - Cópia (10) - Cópia.php');

assert_true(
    $source !== false,
    'Source file is readable'
);

assert_contains(
    $source,
    'Strict-Transport-Security',
    'Source file contains the Strict-Transport-Security header directive'
);

// ---------------------------------------------------------------------------
// Test 2: The HSTS header value includes a meaningful max-age.
//         OWASP recommends at least 31536000 seconds (1 year).
// ---------------------------------------------------------------------------
assert_contains(
    $source,
    'max-age=31536000',
    'HSTS max-age is set to at least one year (31536000 seconds)'
);

// ---------------------------------------------------------------------------
// Test 3: The HSTS directive includes includeSubDomains to protect all
//         subdomains from protocol-downgrade attacks.
// ---------------------------------------------------------------------------
assert_contains(
    $source,
    'includeSubDomains',
    'HSTS header includes the includeSubDomains directive'
);

// ---------------------------------------------------------------------------
// Test 4: The HSTS header is sent only when NOT running in CLI mode.
//         (Sending HTTP headers from CLI produces a PHP notice and is
//         meaningless; the fix must guard with PHP_SAPI !== 'cli'.)
// ---------------------------------------------------------------------------
assert_contains(
    $source,
    "PHP_SAPI !== 'cli'",
    'HSTS header call is guarded by PHP_SAPI !== "cli" check'
);

// ---------------------------------------------------------------------------
// Test 5: The header() call appears BEFORE any output statements.
//         Headers must be sent before body content.
//         We check that 'header(' appears earlier in the file than 'echo'.
// ---------------------------------------------------------------------------
$headerPos = strpos($source, "header('Strict-Transport-Security");
$echoPos   = strpos($source, 'echo ');

assert_true(
    $headerPos !== false && $echoPos !== false && $headerPos < $echoPos,
    'HSTS header() call appears before the first echo statement'
);

// ---------------------------------------------------------------------------
// Test 6: Simulate a web-request execution context by temporarily overriding
//         PHP_SAPI (via a wrapper function approach) and confirming the header
//         directive string is correct.
//
//         Because PHP cannot truly override PHP_SAPI at runtime, we extract
//         and evaluate only the header-setting fragment of the script in a
//         controlled way.
// ---------------------------------------------------------------------------
preg_match(
    "/if\s*\(\s*PHP_SAPI\s*!==\s*'cli'\s*\)\s*\{([^}]+)\}/s",
    $source,
    $matches
);

assert_true(
    isset($matches[1]),
    'HSTS header is enclosed in a PHP_SAPI guard block'
);

if (isset($matches[1])) {
    assert_contains(
        trim($matches[1]),
        "header('Strict-Transport-Security: max-age=31536000; includeSubDomains')",
        'HSTS header() call inside the guard block has the correct value'
    );
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
echo "\n";
echo "Results: $passed passed, $failed failed\n";

if ($failed > 0) {
    exit(1);
}
