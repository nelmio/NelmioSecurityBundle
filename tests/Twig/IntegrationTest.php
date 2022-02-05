<?php

declare(strict_types=1);

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\Tests\Twig;

use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputer;
use Nelmio\SecurityBundle\EventListener\ContentSecurityPolicyListener;
use Nelmio\SecurityBundle\Twig\CSPRuntime;
use Nelmio\SecurityBundle\Twig\NelmioCSPTwigExtension;
use PHPUnit\Framework\TestCase;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;
use Twig\RuntimeLoader\RuntimeLoaderInterface;

class IntegrationTest extends TestCase
{
    public function testItWorksDynamically(): void
    {
        $collectedShas = [];

        $shaComputer = $this->getMockBuilder(ShaComputer::class)
            ->disableOriginalConstructor()
            ->getMock();
        $shaComputer->expects($this->once())
            ->method('computeForScript')
            ->willReturn('sha-script');
        $shaComputer->expects($this->once())
            ->method('computeForStyle')
            ->willReturn('sha-style');

        $listener = $this->getMockBuilder(ContentSecurityPolicyListener::class)
            ->disableOriginalConstructor()
            ->getMock();
        $listener->expects($this->never())
            ->method('addSha');
        $listener->expects($this->once())
            ->method('addScript')
            ->willReturnCallback(static function ($script) use (&$collectedShas, $shaComputer) {
                $collectedShas['script-src'][] = $shaComputer->computeForScript($script);
            });
        $listener->expects($this->once())
            ->method('addStyle')
            ->willReturnCallback(static function ($style) use (&$collectedShas, $shaComputer) {
                $collectedShas['style-src'][] = $shaComputer->computeForStyle($style);
            });

        $cspRuntime = new CSPRuntime($listener);

        $twig = new Environment(new FilesystemLoader(__DIR__.'/templates'));
        $twig->addExtension(new NelmioCSPTwigExtension($shaComputer));
        $loader = $this->createMock(RuntimeLoaderInterface::class);
        $loader->method('load')->willReturnMap([
            [CSPRuntime::class, $cspRuntime],
        ]);
        $twig->addRuntimeLoader($loader);

        $this->assertSame('<script type="text/javascript">console.log(\'123456\');</script>

<style type="text/css">body{ background: black; }</style>
', $twig->render('test-dynamic.twig', ['api_key' => '123456', 'color' => 'black']));

        $this->assertSame(['script-src' => ['sha-script'], 'style-src' => ['sha-style']], $collectedShas);
    }

    public function testItWorksStatically(): void
    {
        $collectedShas = [];

        $shaComputer = $this->getMockBuilder(ShaComputer::class)
            ->disableOriginalConstructor()
            ->getMock();
        $shaComputer->expects($this->once())
            ->method('computeForScript')
            ->willReturn('sha-script');
        $shaComputer->expects($this->once())
            ->method('computeForStyle')
            ->willReturn('sha-style');

        $listener = $this->getMockBuilder(ContentSecurityPolicyListener::class)
            ->disableOriginalConstructor()
            ->getMock();
        $listener->expects($this->exactly(2))
            ->method('addSha')
            ->willReturnCallback(static function ($directive, $sha) use (&$collectedShas) {
                $collectedShas[$directive][] = $sha;
            });
        $listener->expects($this->never())
            ->method('addScript');
        $listener->expects($this->never())
            ->method('addStyle');

        $cspRuntime = new CSPRuntime($listener);

        $twig = new Environment(new FilesystemLoader(__DIR__.'/templates'));
        $twig->addExtension(new NelmioCSPTwigExtension($shaComputer));
        $loader = $this->createMock(RuntimeLoaderInterface::class);
        $loader->method('load')->willReturnMap([
            [CSPRuntime::class, $cspRuntime],
        ]);
        $twig->addRuntimeLoader($loader);

        $this->assertSame('<script type="text/javascript">console.log(\'Hello\');</script>

<style type="text/css">body{ background: red; }</style>
', $twig->render('test-static.twig'));

        $this->assertSame(['script-src' => ['sha-script'], 'style-src' => ['sha-style']], $collectedShas);
    }
}
