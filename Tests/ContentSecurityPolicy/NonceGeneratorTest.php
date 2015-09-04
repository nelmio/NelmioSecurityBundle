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
        $this->assertEquals('12345', $nonceGenerator->generate());
        $this->assertEquals('12345', $nonceGenerator->getCurrentNonce());
        $this->assertEquals("'nonce-12345'", $nonceGenerator->getCurrentNonceForHeaders());
    }

    public function testKeepsNonceTheSameOnFutureGenerateCalls()
    {
        $nonceGenerator = $this->getMockBuilder('Nelmio\SecurityBundle\ContentSecurityPolicy\NonceGenerator')
            ->disableOriginalConstructor()
            ->setMethods(array('buildNonce'))
            ->getMock()
        ;

        $nonceGenerator->expects($this->once())
            ->method('buildNonce')
            ->will($this->onConsecutiveCalls('first-nonce', 'second-nonce'))
        ;


        // nonce should stay the same after the first generate call
        /** @var NonceGenerator $nonceGenerator */
        $this->assertEquals('first-nonce', $nonceGenerator->generate());
        $this->assertEquals('first-nonce', $nonceGenerator->generate());
        $this->assertEquals('first-nonce', $nonceGenerator->generate());
    }
}
