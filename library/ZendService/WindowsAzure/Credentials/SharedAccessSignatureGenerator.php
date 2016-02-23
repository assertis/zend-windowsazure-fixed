<?php
/**
 * @author Rafał Orłowski <rafal.orlowski@assertic.co.uk>
 */

namespace ZendService\WindowsAzure\Credentials;

use Zend\Http\Headers;
use Zend\Http\Request;

class SharedAccessSignatureGenerator
{

    const AZURE_DEFAULT_CONTENT_TYPE = "application/atom+xml;type=entry;charset=utf-8";

    const AZURE_SAS_HEADER_PATTERN = "SharedAccessSignature sig=%s&se=%s&skn=%s&sr=%s";

    /**
     * @param $stringToSign
     * @param $key
     * @return string
     */
    public function generateSignature($stringToSign, $key)
    {
        return urlencode(base64_encode(hash_hmac('sha256',$stringToSign, $key, true)));
    }

    /**
     * @param ...$elements
     * @return string
     */
    public function generateStringToSign(...$elements)
    {
        $elements = array_map(function($e){
            return strtolower(urlencode($e));
        }, $elements);

        return implode("\n", $elements);
    }

    /**
     * @param $method
     * @param $uri
     * @param $user
     * @param $key
     * @param $expiryTime
     * @return Request
     */
    public function generateRequestObject($method, $uri, $user, $key, $expiryTime)
    {
        $stringToSign = $this->generateStringToSign($uri, $expiryTime);
        $sasSig = $this->generateSignature($stringToSign, $key);

        $headers = new Headers();
        $headers->addHeaders([
            "Content-Type" => self::AZURE_DEFAULT_CONTENT_TYPE,
            "Authorization" => sprintf(self::AZURE_SAS_HEADER_PATTERN, $sasSig, $expiryTime, $user, strtolower(urlencode($uri)))
        ]);

        $out = new Request();
        $out->setMethod($method);
        $out->setUri($uri);
        $out->setHeaders($headers);

        return $out;
    }

}
