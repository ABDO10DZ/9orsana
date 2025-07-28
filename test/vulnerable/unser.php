<?php
// Unserialize vulnerability
class Evil {
    public $data = "safe";
    function __wakeup() {
        system("echo PWNED > hacked.txt"); // triggered on unserialize
    }
}

if (isset($_POST['obj'])) {
    $obj = unserialize($_POST['obj']); // Vulnerable to object injection
    echo "<pre>";
    var_dump($obj);
    echo "</pre>";
}
?>
<form method="post">
    <input name="obj" placeholder="Enter serialized object">
    <input type="submit" value="Unserialize">
</form>
