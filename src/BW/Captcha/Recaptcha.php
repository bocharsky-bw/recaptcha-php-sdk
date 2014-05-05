<?php

namespace BW\Captcha;

/*
 * This is a reCAPTCHA PHP SDK.
 *    - Documentation and latest version of source for PHP:
 *          https://developers.google.com/recaptcha/docs/php
 */
class Recaptcha
{

    /**
     * Current version of reCAPTCHA PHP SDK
     */
    const VERSION = '1.11.1';

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
    
    /**
     * @var boolean Whether valid user input or no
     */
    protected $valid = false;
    
    /**
     * @var string The occurred error
     */
    protected $error;


    /**
     * The constructor of objects
     * 
     * @param string $publicKey The client public key
     * @param string $privateKey The client private key
     */
    public function __construct($publicKey = '', $privateKey = '')
    {
        $this->setPublicKey($publicKey);
        $this->setPrivateKey($privateKey);
    }
    
    /**
     * @see $this->getHtml()
     */
    public function __toString()
    {
        return $this->getHtml();
    }


    /**
     * Gets the challenge HTML (javascript and non-javascript version).
     * This is called from the browser, and the resulting reCAPTCHA HTML widget
     * is embedded within the HTML form it was called from.
     * 
     * @param string $error The error given by reCAPTCHA (optional, default is null)
     * @param boolean $use_ssl Should the request be made over ssl? (optional, default is false)
     * @return string The HTML to be embedded in the user's form.
     * @throws \Exception
     */
    public function getHtml($error = null, $use_ssl = false) {
        if ( ! $this->getPublicKey()) {
            throw new \Exception('To use reCAPTCHA you must get an API key from <a href="https://www.google.com/recaptcha/admin/create">https://www.google.com/recaptcha/admin/create</a>');
        }

        if (true === $use_ssl) {
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
     * Calls an HTTP POST function to verify if the user's guess was correct
     * 
     * @param array $extraParams An array of extra variables to post to the server
     * @return $this
     * @throws \Exception
     */
    public function checkAnswer($extraParams = array()) {
        $remoteIp = $_SERVER["REMOTE_ADDR"];
        $challenge = $_POST["recaptcha_challenge_field"];
        $response = $_POST["recaptcha_response_field"];
        
        if ( ! $this->getPrivateKey()) {
            throw new \Exception("To use reCAPTCHA you must get an API key from <a href='https://www.google.com/recaptcha/admin/create'>https://www.google.com/recaptcha/admin/create</a>");
        }

        if ( ! $remoteIp) {
            throw new \Exception("For security reasons, you must pass the remote ip to reCAPTCHA");
        }

        if ( ! $challenge) { // discard spam submissions
            $this->valid = false;
            $this->error = 'incorrect-captcha-sol';
        } else { // or check user input
            $response = $this->httpPost(self::RECAPTCHA_VERIFY_SERVER, '/recaptcha/api/verify',
                    array(
                        'privatekey' => $this->getPrivateKey(),
                        'remoteip' => $remoteIp,
                        'challenge' => $challenge,
                        'response' => $response,
                    ) + $extraParams
                );

            $answers = explode("\n", $response[1]);
            if (trim($answers[0]) == 'true') {
                $this->valid = true;
            } else {
                $this->valid = false;
                $this->error = $answers[1];
            }
        }
        
        return $this;
    }

    /**
     * Submits an HTTP POST to a reCAPTCHA server
     * 
     * @param string $host
     * @param string $path
     * @param array $data
     * @param int port
     * @return array response
     * @throws \Exception
     */
    protected function httpPost($host, $path, array $data, $port = 80) {
        $req = $this->qsencode($data);

        $http_request  = "POST {$path} HTTP/1.0\r\n";
        $http_request .= "Host: {$host}\r\n";
        $http_request .= "Content-Type: application/x-www-form-urlencoded;\r\n";
        $http_request .= "Content-Length: " . strlen($req) . "\r\n";
        $http_request .= "User-Agent: reCAPTCHA/PHP\r\n";
        $http_request .= "\r\n";
        $http_request .= $req;

        $response = '';
        if(false == ($fs = @fsockopen($host, (int)$port, $errno, $errstr, 10))) {
            throw new \Exception('Could not open socket');
        }

        fwrite($fs, $http_request);
        while ( ! feof($fs)) {
            $response .= fgets($fs, 1160); // One TCP-IP packet
        }
        fclose($fs);

        $response = explode("\r\n\r\n", $response, 2);
        return $response;
    }
    
    /**
     * Encodes the given data into a query string format
     * 
     * @param array $data An array of string elements to be encoded
     * @return string Encoded request
     */
    protected function qsencode(array $data = array()) {
        $req = '';
        
        if ($data) {
            foreach ($data as $key => $value) {
                $req .= $key . '=' . urlencode(stripslashes($value)) . '&';
            }
            $req = substr($req, 0, strlen($req) - 1); // Cut the last '&'
        }
        
        return $req;
    }
    
    /**
     * Check user input
     * 
     * @return bool Whether valid user input or no
     */
    public function isValid() {
        return $this->valid;
    }
    
    /**
     * Get occurred error
     * 
     * @return string The occurred error
     */
    public function getError() {
        return $this->error;
    }
    
    /**
     * Get the public key
     * 
     * @return string The public key
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }

    /**
     * Set the public key
     * 
     * @param string $publicKey The public key
     * @return $this
     */
    public function setPublicKey($publicKey)
    {
        $this->publicKey = (string)$publicKey;
        return $this;
    }

    /**
     * Get the private key
     * 
     * @return string The private key
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    /**
     * Set the private key
     * 
     * @param string $privateKey The private key
     * @return $this
     */
    public function setPrivateKey($privateKey)
    {
        $this->privateKey = (string)$privateKey;
        return $this;
    }
    
    public function includeOriginalFunctions() {
        $path = dirname(__FILE__) . '/../../../recaptcha/recaptchalib.php';
        if (is_file($path)) {
            require_once $path;
        }
        return $this;
    }

}
