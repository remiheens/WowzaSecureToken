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
     *
     * @var string url 
     */
    private $url;
    /**
     *
     * @var string path url 
     */
    private $urlPath;
    
    /**
     *
     * @var int index of algorithm used to define hash method
     */
    private $hashMethod = self::SHA256;
    
    /**
     *
     * @var array extra params used to generate token 
     */
    private $params = array();
    
    /**
     * 
     * @param string $prefix Set prefix. 
     *      The prefix value can only have the following characters that are safe to use in URLs:	
     *      alphanumeric characters (a - z, A - Z, 0 - 9), percent sign (%), period (.), underscore (_),
-    *      tilde (~), and hyphen (-).
     * @param string $sharedSecret Set shared secret key
     * @throws WowzaException
     */
    public function __construct($prefix, $sharedSecret)
    {
        $patternPrefix = '|^[\w\d%\._\-~]+$|';
        if(!preg_match($patternPrefix, $prefix))
        {
            throw new WowzaException("Prefix [ " . $prefix . " ] is invalid");
        }
        $this->prefix = $prefix;
        
        $patternSecret = '|^[\w\d]+$|';
        if(!preg_match($patternSecret, $sharedSecret))
        {
            throw new WowzaException("Secret [" . $sharedSecret . "] is invalid");
        }
        $this->sharedSecret = $sharedSecret;
    }

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
     * Set client URL for using in hash
     * 
     * @param string $url
     * @throws WowzaException
     */
    public function setURL($url)
    {
        $urlInfo = parse_url($url);
        if(!isset($urlInfo['path']))
        {
            throw new WowzaException("Invalid url supplied");
        }

        $this->url = $url;
        $this->urlPath = $urlInfo['path'];
    }

    /**
     * 
     * @return null|string
     */
    public function getURL()
    {
        return $this->url;
    }

    /**
     * Set hash method , use constants.
     * 
     * @param int $hashMethod
     * @throws WowzaException
     */
    public function setHashMethod($hashMethod)
    {
        if(!isset($this->algorithms[$hashMethod]))
        {
            throw new WowzaException("Algorithm [" . $hashMethod . "] not defined");
        }
        $this->hashMethod = $hashMethod;
    }

    /**
     * 
     * @return null|int
     */
    public function getHashMethod()
    {
        return $this->hashMethod;
    }
    
    /**
     * add extra params to hash generation
     * 
     * @param array $params
     * @throws WowzaException
     */
    public function setExtraParams($params)
    {
        if(!is_array($params))
        {
            throw new WowzaException("\$params must be an array");
        }
        
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
        
        $this->params = $params;
    }
    
    /**
     * 
     * @return array
     */
    public function getParams()
    {
        return $this->params;
    }

    /**
     * 
     * @return null|string
     */
    public function getSharedSecret()
    {
        return $this->sharedSecret;
    }


    /**
     * 
     * @return null|string
     */
    public function getPrefix()
    {
        return $this->prefix;
    }

    /**
     * Get hash token
     * 
     * @return string
     * @throws WowzaException
     */
    public function getHash()
    {
        if(!$this->sharedSecret)
        {
            throw new WowzaException("SharedSecret is not set");
        }
        $query = $this->_paramsToQueryString();

        $path = ltrim($this->urlPath, '/');

        $pathItems = explode('/', $path);
        if(count($pathItems) < 2)
        {
            throw new WowzaException("Application or stream is invalid");
        }

        $path = "";

        foreach ($pathItems as $k => $pathItem) {
            if(1 === preg_match('/(^Manifest|\.m3u8|\.f4m|\.mpd)/',$pathItem)){
                break;
            }

            if (false !== strpos($pathItem, 'redirect') && $k === 0) {
                continue;
            }
            
            $path .= $pathItem;
            if(count($pathItems)-1 != $k) {
                $path .= '/';
            }
        }
        if(strrpos($path, '/') === strlen($path)-1) {
            $path = substr($path, 0, -1);
        }

        $path .= "?".$query;

        return strtr(base64_encode(hash($this->algorithms[$this->hashMethod], $path, true)),'+/','-_');
    }
    
    /**
     * 
     * Get full URL to use in JWplayer
     * 
     * @return string
     */
    public function getFullURL()
    {
        return $this->url."?".http_build_query($this->params).'&'.$this->prefix.'hash='.$this->getHash();
    }

    private function _paramsToQueryString()
    {
        $params = $this->params;
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
}
