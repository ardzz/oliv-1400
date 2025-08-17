<?php
function validateAndCalculate($input) {
    // Strict whitelist validation
    if (!preg_match('/^[0-9+\-*\/().\ ]+$/', $input)) {
        throw new Exception("Invalid characters in expression");
    }

    // Additional safety checks
    if (strpos($input, ';') !== false ||
        strpos($input, '|') !== false ||
        strpos($input, '&') !== false ||
        strpos($input, '$') !== false ||
        strpos($input, '`') !== false) {
        throw new Exception("Potentially dangerous characters detected");
    }

    // Use escapeshellarg for safe shell execution
    $safeInput = escapeshellarg($input);
    $result = shell_exec("echo $safeInput | bc 2>/dev/null");

    if ($result === null || trim($result) === '') {
        throw new Exception("Invalid mathematical expression");
    }

    return trim($result);
}

// In your main code:
if($str !== ""){
    try {
        $result = validateAndCalculate($str);
        echo htmlspecialchars($str) . " = " . htmlspecialchars($result);
    } catch (Exception $e) {
        echo "Error: " . htmlspecialchars($e->getMessage());
    }
}
?>