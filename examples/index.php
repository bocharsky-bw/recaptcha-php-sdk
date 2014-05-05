<?php

include_once __DIR__ .'/../src/BW/Captcha/Recaptcha.php';

$re = new \BW\Captcha\Recaptcha(
        '6LcO__ISAAAAACKCCgXgtlqLa1xD2rZtYA0MzY5g', // input your public key here
        '6LcO__ISAAAAACZwnTN8zOrB3TdeA74mclRqsrpL'  // input your private key here
    );

$response = '';
if (0 === strcasecmp($_SERVER['REQUEST_METHOD'], 'POST')) {
    if ($re->checkAnswer()->isValid()) {
        $response = 'Congrats! Valid input.';
    } else {
        $response = 'Error occurred: ' . $re->getError();
    }
}
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>reCAPTCHA</title>
</head>
<body><!-- the body tag is required or the CAPTCHA may not show on some browsers -->
    <?php if ($response) : ?>
        <h1><?php print $response ?></h1>
    <?php else : ?>
        <h1>Please, enter the text from image</h1>
    <?php endif ?>
    <form method="post" action="">
        <?php print $re->getHtml(); ?>
        <input type="submit" />
    </form>
</body>
</html>