<?php
include "rce.php";
include "unser.php";
include "lfi.php";
include "secrets.php";

echo "<h2>Welcome to the Dangerous PHP App</h2>";

if (isset($_GET['page'])) {
    include $_GET['page']; // LFI vulnerability
}
?>
<form method="get">
    <input name="page" value="index.php">
    <input type="submit" value="Load Page">
</form>
