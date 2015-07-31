<?php
namespace Nelmio\SecurityBundle\Tests\ContentSecurityPolicy;

use Nelmio\SecurityBundle\ContentSecurityPolicy\NonceGenerator;
use Psr\Log\LoggerInterface;

class NonceGeneratorTest extends \PHPUnit_Framework_TestCase
{
    public function testReturnsValidNonce()
    {
        $nonceGenerator = $this->getMockBuilder('Nelmio\SecurityBundle\ContentSecurityPolicy\NonceGenerator')
            ->disableOriginalConstructor()
            ->setMethods(array('buildNonce'))
            ->getMock()
        ;

        $nonceGenerator->expects($this->once())
            ->method('buildNonce')
            ->willReturn('12345')
        ;

        /** @var NonceGenerator $nonceGenerator */
        $this->assertEquals("'nonce-12345'", $nonceGenerator->generate());
        $this->assertEquals("12345", $nonceGenerator->getCurrentToken());
    }
}
