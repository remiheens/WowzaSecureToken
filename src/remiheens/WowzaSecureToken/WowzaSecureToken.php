<?php

namespace remiheens\WowzaSecureToken;

class WowzaSecureToken
{

    /**
     * SHA-256 algorithm
     */
    const SHA256 = 1;

    /**
     * SHA-384 algorithm
     */
    const SHA384 = 2;

    /**
     * SHA-512 algorithm
     */
    const SHA512 = 3;

    /**
     * Constant mapping to string values for php hash function
     * @var array
     */
    private $algorithms = array(
        self::SHA256 => 'sha256',
        self::SHA384 => 'sha384',
        self::SHA512 => 'sha512',
    );

    /**
     * @var string|null client IP for validation in Wowza
     */
    private $clientIP = null;

    /**
     * @var string prefix for all query parameters
     */
    private $prefix;

    /**
     * @var string secret key
     */
    private $sharedSecret;

    /**
     * Set client IP for using in hash
     *
     * @param string $ip
     * @throws WowzaException
     */
    public function setClientIP($ip)
    {
        if(!filter_var($ip, FILTER_VALIDATE_IP))
        {
            throw new WowzaException("User IP (" . $ip . ") is invalid");
        }
        $this->clientIP = $ip;
    }

    /**
     * @return null|string
     */
    public function getClientIP()
    {
        return $this->clientIP;
    }

    /**
     * Set shared secret key
     *
     * @param $secret string
     * @throws WowzaException
     */
    public function setSharedSecret($secret)
    {
        $pattern = '|^[\w\d]+$|';
        if(!preg_match($pattern, $secret))
        {
            throw new WowzaException("Secret [" . $secret . "] is invalid");
        }
        $this->sharedSecret = $secret;
    }

    public function getSharedSecret()
    {
        return $this->sharedSecret;
    }

    /**
     * Set prefix. The prefix value can only have the following characters that are safe to use in URLs:
     * alphanumeric characters (a - z, A - Z, 0 - 9), percent sign (%), period (.), underscore (_),
     * tilde (~), and hyphen (-).
     *
     * @param $prefix
     * @throws WowzaException
     */
    public function setPrefix($prefix)
    {
        $pattern = '|^[\w\d%\._\-~]+$|';
        if(!preg_match($pattern, $prefix))
        {
            throw new WowzaException("Prefix [ " . $prefix . " ] is invalid");
        }
        $this->prefix = $prefix;
    }

    public function getPrefix()
    {
        return $this->prefix;
    }

    public function getHash($contentUrl, $hashMethod, $params = array())
    {
        $this->_verifyConfiguration($hashMethod);
        $query = $this->_paramsToQueryString($params);

        $urlInfo = parse_url($contentUrl);
        if(!isset($urlInfo['path']))
        {
            throw new WowzaException("Invalid url supplied");
        }

        $path = ltrim($urlInfo['path'], '/');

        $pathItems = explode('/', $path);
        if(count($pathItems) < 2)
        {
            throw new WowzaException("Application or stream is invalid");
        }

        $query = $pathItems[0] . "/" . $pathItems[1] . "?" . $query;

        return base64_encode(hash($this->algorithms[$hashMethod], $query, true));
    }

    private function _paramsToQueryString($params)
    {
        if($this->prefix)
        {
            foreach($params as $key => $param)
            {
                if(strpos($key, $this->prefix) === false)
                {
                    $params[$this->prefix . $key] = $param;
                    unset($params[$key]);
                }
            }
        }

        if($this->clientIP !== null)
        {
            $params[$this->clientIP] = "";
        }

        $params[$this->sharedSecret] = "";
        ksort($params);

        $query = '';
        foreach($params as $k => $v)
        {
            $query .= '&' . $k;
            if(isset($v) && !empty($v))
            {
                $query .= '=' . $v;
            }
        }
        return trim($query, '&');
    }

    private function _verifyConfiguration($hashMethod)
    {
        if(!$this->sharedSecret)
        {
            throw new WowzaException("SharedSecret is not set");
        }

        if(!isset($this->algorithms[$hashMethod]))
        {
            throw new WowzaException("Algorithm [" . $hashMethod . "] not defined");
        }
    }

}
