<?php

include_once __DIR__ .'/../src/BW/Captcha/Recaptcha.php';

$re = new \BW\Captcha\Recaptcha('6LcT9fESAAAAADYP6P-m718_8jW3HAtFF-2OkkuU', '6LcT9fESAAAAACU1kJwoJZBOOqADiyL-KATRCIYi');

?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>reCAPTCHA</title>
</head>
<body><!-- the body tag is required or the CAPTCHA may not show on some browsers -->
    <form method="post" action="verify.php">
        <?php print $re->getHtml(); ?>
        <input type="submit" />
    </form>
</body>
</html>