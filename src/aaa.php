<?php
// Simulated insecure PHP file with secrets and external calls for secret-scanner testing

// AWS credentials
$aws_access_key = "AKIAIOSFODNN7EXAMPLE";
$aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// GitHub token
$github_token = "ghp_FAKEPERSONALACCESSTOKEN1234567890abcde";

// Stripe secret key
$stripe_secret_key = "sk_live_51FakeKeyExample9876543210abcdef";

// Basic Auth credentials
$basic_auth_user = "admin";
$basic_auth_pass = "SuperSecret123!";

// Private RSA Key
$private_key = <<<EOD
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAuYRAKE+NScOPg5vVtGpF2Ck9vPzzZZzZ5o8oMIeD+vYv7Rc0
4Zh1uVt88oOPAgMBAAECggEAErJoq9xQJK7B1P9aD7k1KcYZD+ZHZl1/fakekey
-----END RSA PRIVATE KEY-----
EOD;

// Slack webhook
$slack_webhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";

// MySQL creds
$db_host = "localhost";
$db_user = "root";
$db_pass = "toor";
$db_name = "securedb";

function sendSlackNotification($message, $webhook) {
    $payload = json_encode(["text" => $message]);
    $ch = curl_init($webhook);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_exec($ch);
    curl_close($ch);
}

function fetchGitHubRepos($token) {
    $ch = curl_init("https://api.github.com/user/repos");
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Authorization: token $token",
        "User-Agent: Secret-Scanner-Test"
    ]);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}

function chargeCardWithStripe($key) {
    $ch = curl_init("https://api.stripe.com/v1/charges");
    curl_setopt($ch, CURLOPT_USERPWD, $key . ":");
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        "amount" => 1000,
        "currency" => "usd",
        "source" => "tok_visa",
        "description" => "Charge for test@example.com"
    ]));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}

function connectToDatabase($host, $user, $pass, $db) {
    $mysqli = new mysqli($host, $user, $pass, $db);
    if ($mysqli->connect_error) {
        die("Connection failed: " . $mysqli->connect_error);
    }
    return $mysqli;
}

// Execute fake functions
sendSlackNotification("Secret test payload sent", $slack_webhook);
fetchGitHubRepos($github_token);
chargeCardWithStripe($stripe_secret_key);
$db = connectToDatabase($db_host, $db_user, $db_pass, $db_name);

echo "Simulated insecure PHP actions complete.\n";
?>
