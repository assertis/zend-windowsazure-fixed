<?php
/**
 * @author Rafał Orłowski <rafal.orlowski@assertic.co.uk>
 */

namespace ZendServiceTest\WindowsAzure\Credentials;


use Zend\Http\Headers;
use Zend\Http\Request;
use ZendService\WindowsAzure\Credentials\SharedAccessSignatureGenerator;

class SharedAccessSignatureGeneratorTest extends \PHPUnit_Framework_TestCase
{

    public function test_generateSignature()
    {
        $stringToSign = "https%3a%2f%2fgatwick-data-hub-test.servicebus.windows.net%3a443%2fpartners%2fgtr%2fto%2fmessages%2fhead%3ftimeout%3d60"."\n"."1456149446";
        $key = "SNH8/+8EV1nbDqQnZydLVkFAdQqdwMJ5FaqeXGnaQGI=";

        $generator = new SharedAccessSignatureGenerator();
        $result = $generator->generateSignature($stringToSign, $key);

        $this->assertEquals("JLwjJA2oiWmTkonn84wxjrOzQUrPPHDUxu7IiAV2WEY%3D", $result);
    }

    public function test_generateStringToSign()
    {
        $uri = "https://gatwick-data-hub-test.servicebus.windows.net/partners/gtr/to/messages/head?timeout=60";
        $expiry = "1456149446";

        $generator = new SharedAccessSignatureGenerator();
        $result = $generator->generateStringToSign($uri, $expiry);
        $expectedResult = "https%3a%2f%2fgatwick-data-hub-test.servicebus.windows.net%2fpartners%2fgtr%2fto%2fmessages%2fhead%3ftimeout%3d60"."\n"."1456149446";

        $this->assertEquals($expectedResult, $result);
    }

    public function test_generateRequestObject()
    {
        $uri = 'https://gatwick-data-hub-test.servicebus.windows.net/partners/gtr/to/messages/head?timeout=60';
        $expiryTime = 1456209757;
        $user = "gtrto";
        $key = "SNH8/+8EV1nbDqQnZydLVkFAdQqdwMJ5FaqeXGnaQGI=";

        $generator = new SharedAccessSignatureGenerator();
        $result = $generator->generateRequestObject('DELETE', $uri, $user, $key, $expiryTime);

        $expectedResult = new Request();
        $expectedResult->setMethod('DELETE');
        $expectedResult->setUri($uri);
        $headers = new Headers();
        $headers->addHeaders([
            "Content-Type" => "application/atom+xml;type=entry;charset=utf-8",
            "Authorization" => "SharedAccessSignature sig=vhuS8J4cteEYiaynyOV%2Bsi6SsTPUIhj3JwTe7%2BH%2B9Eg%3D&se=1456209757&skn=gtrto&sr=https%3a%2f%2fgatwick-data-hub-test.servicebus.windows.net%2fpartners%2fgtr%2fto%2fmessages%2fhead%3ftimeout%3d60"
        ]);

        $expectedResult->setHeaders($headers);

        // if test won't pass, try to regenerate token, maybe I made a mistake
        $this->assertEquals($expectedResult, $result);

    }

}