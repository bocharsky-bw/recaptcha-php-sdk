<?php

namespace BW\Captcha;

/*
 * This is a reCAPTCHA PHP SDK.
 *    - Documentation and latest version of source for PHP:
 *          https://developers.google.com/recaptcha/docs/php
 */
class Recaptcha
{

    const VERSION = '1.11.0';

    /**
     * The reCAPTCHA API server URL
     */
    const RECAPTCHA_API_SERVER = 'http://www.google.com/recaptcha/api';

    /**
     * The reCAPTCHA API secure server URL
     */
    const RECAPTCHA_API_SECURE_SERVER = 'https://www.google.com/recaptcha/api';

    /**
     * The reCAPTCHA API verify server URL
     */
    const RECAPTCHA_VERIFY_SERVER = 'www.google.com';

    /**
     * @var string The client public key
     */
    private $publicKey;

    /**
     * @var string The client private key
     */
    private $privateKey;


    public function __construct($publicKey = '', $privateKey = '')
    {
        $this->setPublicKey($publicKey);
        $this->setPrivateKey($privateKey);
    }
    
    public function __toString() {
        return $this->getHtml();
    }


    /**
     * Gets the challenge HTML (javascript and non-javascript version).
     * This is called from the browser, and the resulting reCAPTCHA HTML widget
     * is embedded within the HTML form it was called from.
     * @param string $publicKey A public key for reCAPTCHA
     * @param string $error The error given by reCAPTCHA (optional, default is null)
     * @param boolean $use_ssl Should the request be made over ssl? (optional, default is false)

     * @return string - The HTML to be embedded in the user's form.
     */
    public function getHtml($publicKey = null, $error = null, $use_ssl = false) {
        if ($publicKey) {
            $this->setPublicKey($publicKey);
        }

        if ( ! $this->getPublicKey()) {
            throw new \Exception('To use reCAPTCHA you must get an API key from <a href="https://www.google.com/recaptcha/admin/create">https://www.google.com/recaptcha/admin/create</a>');
        }

        if ($use_ssl) {
            $server = self::RECAPTCHA_API_SECURE_SERVER;
        } else {
            $server = self::RECAPTCHA_API_SERVER;
        }

        $errorpart = '';
        if ($error) {
            $errorpart = "&amp;error=" . $error;
        }

        return '<script type="text/javascript" src="'. $server . '/challenge?k=' . $this->getPublicKey() . $errorpart . '"></script>'. PHP_EOL
                .'<noscript>'. PHP_EOL
                .'    <iframe src="'. $server . '/noscript?k=' . $this->getPublicKey() . $errorpart . '" height="300" width="500" frameborder="0"></iframe><br/>'. PHP_EOL
                .'    <textarea name="recaptcha_challenge_field" rows="3" cols="40"></textarea>'. PHP_EOL
                .'    <input type="hidden" name="recaptcha_response_field" value="manual_challenge"/>'. PHP_EOL
                .'</noscript>'. PHP_EOL;
    }


    /**
     * @return string
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }

    /**
     * @param string $publicKey
     * @return $this
     */
    public function setPublicKey($publicKey)
    {
        $this->publicKey = (string)$publicKey;
        return $this;
    }

    /**
     * @return string
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    /**
     * @param string $privateKey
     * @return $this
     */
    public function setPrivateKey($privateKey)
    {
        $this->privateKey = (string)$privateKey;
        return $this;
    }


}
