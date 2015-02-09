# WowzaSecureToken

PHP library to create secure token for Wowza server

## Installation

Install with Composer.
First, install composer on your server

```
$ curl -s http://getcomposer.org/installer | php
```

Create/Edit your `composer.json` file

```
{
    "require": {
        "remiheens/php-wowza-securetoken" : "0.1.*"
    }
}
```

Install the library

```
$ composer install
```

Add composer Autoloader to your php file
```php
require_once __DIR__.'/vendor/autoload.php';
```

## Example
```php
$wowzaToken = new \remiheens\WowzaSecureToken\WowzaSecureToken('wowzaprefix','mySharedSecret');
$wowzaToken->setClientIP($_SERVER['REMOTE_ADDR']);
$wowzaToken->setURL('rtmp://192.168.1.19:1935/vod/mp4:sample.mp4');
$wowzaToken->setHashMethod(\remiheens\WowzaSecureToken\WowzaSecureToken::SHA256);

$starttime = time();
$endtime = strtotime('+3 HOUR');
$params = array(
    'endtime' => $endtime,
    'starttime' => $starttime,
    'CustomParam1' => 'CustomValue'
);

$wowzaToken->setExtraParams($params);

$hash = $wowzaToken->getHash();

$url = $wowzaToken->getFullURL();

```