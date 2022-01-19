<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\Tests\Twig;

use Nelmio\SecurityBundle\Twig\NelmioCSPTwigExtension;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;

class IntegrationTest extends \PHPUnit\Framework\TestCase
{
    public function testItWorksDynamically()
    {
        $collectedShas = [];

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

        $twig = new Environment(new FilesystemLoader(__DIR__.'/templates'));
        $twig->addExtension(new NelmioCSPTwigExtension($listener, $shaComputer));

        $this->assertSame('<script type="text/javascript">console.log(\'123456\');</script>

<style type="text/css">body{ background: black; }</style>
', $twig->render('test-dynamic.twig', ['api_key' => '123456', 'color' => 'black']));

        $this->assertSame(['script-src' => ['sha-script'], 'style-src' => ['sha-style']], $collectedShas);
    }

    public function testItWorksStatically()
    {
        $collectedShas = [];

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

        $twig = new Environment(new FilesystemLoader(__DIR__.'/templates'));
        $twig->addExtension(new NelmioCSPTwigExtension($listener, $shaComputer));

        $this->assertSame('<script type="text/javascript">console.log(\'Hello\');</script>

<style type="text/css">body{ background: red; }</style>
', $twig->render('test-static.twig'));

        $this->assertSame(['script-src' => ['sha-script'], 'style-src' => ['sha-style']], $collectedShas);
    }
}
