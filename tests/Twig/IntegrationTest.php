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

use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;
use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSetBuilderInterface;
use Nelmio\SecurityBundle\ContentSecurityPolicy\NonceGeneratorInterface;
use Nelmio\SecurityBundle\ContentSecurityPolicy\PolicyManager;
use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputerInterface;
use Nelmio\SecurityBundle\EventListener\ContentSecurityPolicyListener;
use Nelmio\SecurityBundle\Twig\CSPRuntime;
use Nelmio\SecurityBundle\Twig\NelmioCSPTwigExtension;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;
use Twig\RuntimeLoader\RuntimeLoaderInterface;

class IntegrationTest extends TestCase
{
    public function testItWorksDynamically(): void
    {
        $shaComputer = $this->getMockBuilder(ShaComputerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $shaComputer->expects($this->once())
            ->method('computeForScript')
            ->willReturn('sha-script');
        $shaComputer->expects($this->once())
            ->method('computeForStyle')
            ->willReturn('sha-style');

        $policyManager = new PolicyManager();

        $listener = new ContentSecurityPolicyListener(
            $this->createDirectiveSetBuilderMock(new DirectiveSet($policyManager)),
            $this->createDirectiveSetBuilderMock(new DirectiveSet($policyManager)),
            $this->createStub(NonceGeneratorInterface::class),
            $shaComputer
        );

        $cspRuntime = new CSPRuntime($listener);

        $twig = new Environment(new FilesystemLoader(__DIR__.'/templates'));
        $twig->addExtension(new NelmioCSPTwigExtension($shaComputer));
        $loader = $this->createMock(RuntimeLoaderInterface::class);
        $loader->method('load')->willReturnMap([
            [CSPRuntime::class, $cspRuntime],
        ]);
        $twig->addRuntimeLoader($loader);

        $listener->onKernelRequest(new RequestEvent(
            $this->createStub(HttpKernelInterface::class),
            Request::create('/'),
            HttpKernelInterface::MAIN_REQUEST
        ));

        $this->assertSame('<script type="text/javascript">console.log(\'123456\');</script>

<style type="text/css">body{ background: black; }</style>
', $twig->render('test-dynamic.twig', ['api_key' => '123456', 'color' => 'black']));

        $getSha = \Closure::bind(static function (ContentSecurityPolicyListener $listener): ?array {
            return $listener->sha;
        }, null, ContentSecurityPolicyListener::class);

        $this->assertSame(['script-src' => ['sha-script'], 'style-src' => ['sha-style']], $getSha($listener));
    }

    public function testItWorksStatically(): void
    {
        $shaComputer = $this->getMockBuilder(ShaComputerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $shaComputer->expects($this->once())
            ->method('computeForScript')
            ->willReturn('sha-script');
        $shaComputer->expects($this->once())
            ->method('computeForStyle')
            ->willReturn('sha-style');

        $policyManager = new PolicyManager();

        $listener = new ContentSecurityPolicyListener(
            $this->createDirectiveSetBuilderMock(new DirectiveSet($policyManager)),
            $this->createDirectiveSetBuilderMock(new DirectiveSet($policyManager)),
            $this->createStub(NonceGeneratorInterface::class),
            $shaComputer
        );

        $cspRuntime = new CSPRuntime($listener);

        $twig = new Environment(new FilesystemLoader(__DIR__.'/templates'));
        $twig->addExtension(new NelmioCSPTwigExtension($shaComputer));
        $loader = $this->createMock(RuntimeLoaderInterface::class);
        $loader->method('load')->willReturnMap([
            [CSPRuntime::class, $cspRuntime],
        ]);
        $twig->addRuntimeLoader($loader);

        $listener->onKernelRequest(new RequestEvent(
            $this->createStub(HttpKernelInterface::class),
            Request::create('/'),
            HttpKernelInterface::MAIN_REQUEST
        ));

        $this->assertSame('<script type="text/javascript">console.log(\'Hello\');</script>

<style type="text/css">body{ background: red; }</style>
', $twig->render('test-static.twig'));

        $getSha = \Closure::bind(static function (ContentSecurityPolicyListener $listener): ?array {
            return $listener->sha;
        }, null, ContentSecurityPolicyListener::class);

        $this->assertSame(['script-src' => ['sha-script'], 'style-src' => ['sha-style']], $getSha($listener));
    }

    private function createDirectiveSetBuilderMock(DirectiveSet $directiveSet): DirectiveSetBuilderInterface
    {
        $mock = $this->createMock(DirectiveSetBuilderInterface::class);
        $mock->method('buildDirectiveSet')->willReturn($directiveSet);

        return $mock;
    }
}
