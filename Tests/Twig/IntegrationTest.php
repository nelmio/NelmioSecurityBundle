<?php

namespace Nelmio\SecurityBundle\Tests\Twig;

use Nelmio\SecurityBundle\Twig\NelmioCSPTwigExtension;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;

class IntegrationTest extends \PHPUnit\Framework\TestCase
{
    public function testItWorksDynamically()
    {
        $collectedShas = array();

        $shaComputer = $this->getMockBuilder('Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputer')
            ->disableOriginalConstructor()
            ->getMock();
        $shaComputer->expects($this->exactly(1))
            ->method('computeForScript')
            ->will($this->returnValue('sha-script'));
        $shaComputer->expects($this->exactly(1))
            ->method('computeForStyle')
            ->will($this->returnValue('sha-style'));

        $listener = $this->getMockBuilder('Nelmio\SecurityBundle\EventListener\ContentSecurityPolicyListener')
            ->disableOriginalConstructor()
            ->getMock();
        $listener->expects($this->never())
            ->method('addSha');
        $listener->expects($this->exactly(1))
            ->method('addScript')
            ->will($this->returnCallback(function ($script) use (&$collectedShas, $shaComputer) {
                $collectedShas['script-src'][] = $shaComputer->computeForScript($script);
            }));
        $listener->expects($this->exactly(1))
            ->method('addStyle')
            ->will($this->returnCallback(function ($style) use (&$collectedShas, $shaComputer) {
                $collectedShas['style-src'][] = $shaComputer->computeForStyle($style);
            }));

        if (class_exists(Environment::class)) {
            $twig = new Environment(new FilesystemLoader(__DIR__.'/templates'));
        } else {
            $twig = new \Twig_Environment(new \Twig_Loader_Filesystem(__DIR__.'/templates'));
        }

        $twig->addExtension(new NelmioCSPTwigExtension($listener, $shaComputer));

        $this->assertSame('<script type="text/javascript">console.log(\'123456\');</script>

<style type="text/css">body{ background: black; }</style>
', $twig->render('test-dynamic.twig', array('api_key' => '123456', 'color' => 'black')));

        $this->assertSame(array('script-src' => array('sha-script'), 'style-src' => array('sha-style')), $collectedShas);
    }

    public function testItWorksStatically()
    {
        $collectedShas = array();

        $shaComputer = $this->getMockBuilder('Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputer')
            ->disableOriginalConstructor()
            ->getMock();
        $shaComputer->expects($this->exactly(1))
            ->method('computeForScript')
            ->will($this->returnValue('sha-script'));
        $shaComputer->expects($this->exactly(1))
            ->method('computeForStyle')
            ->will($this->returnValue('sha-style'));

        $listener = $this->getMockBuilder('Nelmio\SecurityBundle\EventListener\ContentSecurityPolicyListener')
            ->disableOriginalConstructor()
            ->getMock();
        $listener->expects($this->exactly(2))
            ->method('addSha')
            ->will($this->returnCallback(function ($directive, $sha) use (&$collectedShas) {
                $collectedShas[$directive][] = $sha;
            }));
        $listener->expects($this->never())
            ->method('addScript');
        $listener->expects($this->never())
            ->method('addStyle');

        $twig = new \Twig_Environment(new \Twig_Loader_Filesystem(__DIR__.'/templates'));
        $twig->addExtension(new NelmioCSPTwigExtension($listener, $shaComputer));

        $this->assertSame('<script type="text/javascript">console.log(\'Hello\');</script>

<style type="text/css">body{ background: red; }</style>
', $twig->render('test-static.twig'));

        $this->assertSame(array('script-src' => array('sha-script'), 'style-src' => array('sha-style')), $collectedShas);
    }
}
