<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" integrity="sha384-MCw98/SFnGE8fJT3GXwEOngsV7Zt27NXFoaoApmYm81iuXoPkFOJwJ8ERdknLPMO" crossorigin="anonymous">
    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.3/umd/popper.min.js" integrity="sha384-ZMP7rVo3mIykV+2+9J3UJ46jBk0WLaUAdn689aCwoqbBJiSnjAK/l8WvCWPIPm49" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/js/bootstrap.min.js" integrity="sha384-ChfqqxuZUCnJSK3+MXmPNIyE6ZbWh2IMqE241rYiqJxyMiZ6OW/JmZQ5stwEULTy" crossorigin="anonymous"></script>
    <title>calc</title>
</head>
<body>
<div class="container">
    <div class="row">
        <div class="col-md-6">

            </br>
            </br>
            <h2>calculator</h2>
            </br>
            <?php
            $str = "";
            $result = "";
            $error = "";

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

            if(!empty($_GET)){
                $str = $_GET["calc"];
                try {
                    $result = validateAndCalculate($str);
                    echo htmlspecialchars($str) . " = " . htmlspecialchars($result);
                } catch (Exception $e) {
                    echo "Error: " . htmlspecialchars($e->getMessage());
                }
            }
            ?>

            <form class="form-inline" action="./rce.php">
                <div class="form-group mb-2 ">
                    <label for="staticEmail2" class="sr-only">Input</label>
                </div>
                <div class="form-group mx-sm-3 mb-2">
                    <input type="text" name="calc" class="form-control" placeholder="1+1" value="<?php echo htmlspecialchars($str, ENT_QUOTES, 'UTF-8');?>">
                </div>
                <button type="submit" class="btn btn-primary mb-2">calculate</button>
            </form>

            </br>
            <?php
            if($str !== ""){
                if($error !== "") {
                    ?>
                    <div class="alert alert-danger" role="alert">
                        <?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?>
                    </div>
                    <?php
                } else {
                    ?>
                    <div class="alert alert-primary" role="alert">
                        <?php
                        echo htmlspecialchars($str, ENT_QUOTES, 'UTF-8') . " = " . htmlspecialchars($result, ENT_QUOTES, 'UTF-8');
                        ?>
                    </div>
                    <?php
                }
            }
            ?>
        </div>
    </div>
</div>

</body>
</html>