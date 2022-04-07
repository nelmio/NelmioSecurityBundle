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

namespace Nelmio\SecurityBundle\Tests\Listener;

use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;
use Nelmio\SecurityBundle\ContentSecurityPolicy\NonceGeneratorInterface;
use Nelmio\SecurityBundle\ContentSecurityPolicy\PolicyManager;
use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputerInterface;
use Nelmio\SecurityBundle\EventListener\ContentSecurityPolicyListener;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ContentSecurityPolicyListenerTest extends ListenerTestCase
{
    /**
     * @var Stub&HttpKernelInterface
     */
    private $kernel;

    /**
     * @var Stub&NonceGeneratorInterface
     */
    private $nonceGenerator;

    /**
     * @var MockObject&ShaComputerInterface
     */
    private $shaComputer;

    protected function setUp(): void
    {
        $this->kernel = $this->createStub(HttpKernelInterface::class);
        $this->nonceGenerator = $this->createStub(NonceGeneratorInterface::class);

        $this->shaComputer = $this->createMock(ShaComputerInterface::class);
        $this->shaComputer
            ->method('computeForScript')
            ->willReturn('sha-script');
        $this->shaComputer
            ->method('computeForStyle')
            ->willReturn('sha-style');
    }

    public function tesInvalidArgumentException(): void
    {
        $listener = $this->buildSimpleListener(['default-src' => "default.example.org 'self'"]);

        $this->expectException(\InvalidArgumentException::class);

        $listener->getNonce('prout');
    }

    public function testDefault(): void
    {
        $listener = $this->buildSimpleListener(['default-src' => "default.example.org 'self'"]);
        $response = $this->callListener($listener, '/', true);

        $this->assertSame(
            "default-src default.example.org 'self'",
            $response->headers->get('Content-Security-Policy')
        );
    }

    public function testDefaultWithSignatures(): void
    {
        $listener = $this->buildSimpleListener(['default-src' => "default.example.org 'self'"]);
        $response = $this->callListener($listener, '/', true, 'text/html', ['signatures' => ['script-src' => ['sha-1']]]);

        $this->assertSame(
            "default-src default.example.org 'self'; script-src default.example.org 'self' 'unsafe-inline' 'sha-1'",
            $response->headers->get('Content-Security-Policy')
        );
    }

    public function testEvenWithUnsafeInlineItAppliesSignature(): void
    {
        $listener = $this->buildSimpleListener(['default-src' => "default.example.org 'self'", 'script-src' => "'self' 'unsafe-inline'"]);
        $response = $this->callListener($listener, '/', true, 'text/html', ['signatures' => ['script-src' => ['sha-1']]]);

        $this->assertSame(
            "default-src default.example.org 'self'; script-src 'self' 'unsafe-inline' 'sha-1'",
            $response->headers->get('Content-Security-Policy')
        );
    }

    public function testDefaultWithSignaturesAndNonce(): void
    {
        $this->nonceGenerator
            ->method('generate')
            ->willReturn('12345');

        $listener = $this->buildSimpleListener(['default-src' => "default.example.org 'self'"]);
        $response = $this->callListener($listener, '/', true, 'text/html', ['signatures' => ['script-src' => ['sha-1']]], 3);

        $this->assertSame(
            "default-src default.example.org 'self'; script-src default.example.org 'self' 'unsafe-inline' 'sha-1' 'nonce-12345'; style-src default.example.org 'self' 'unsafe-inline' 'nonce-12345'",
            $response->headers->get('Content-Security-Policy')
        );
    }

    public function testDefaultWithAddScript(): void
    {
        $this->nonceGenerator
            ->method('generate')
            ->willReturn('12345');

        $listener = $this->buildSimpleListener(['default-src' => "default.example.org 'self'"]);
        $response = $this->callListener($listener, '/', true, 'text/html', ['scripts' => ['<script></script>'], 'styles' => ['<style></style>']], 3);

        $this->assertSame(
            "default-src default.example.org 'self'; script-src default.example.org 'self' 'unsafe-inline' 'sha-script' 'nonce-12345'; style-src default.example.org 'self' 'unsafe-inline' 'sha-style' 'nonce-12345'",
            $response->headers->get('Content-Security-Policy')
        );
    }

    public function testWithContentTypeRestriction(): void
    {
        $listener = $this->buildSimpleListener(['default-src' => "default.example.org 'self'"], false, true, ['text/html']);
        $response = $this->callListener($listener, '/', true, 'application/json');

        $this->assertNull($response->headers->get('Content-Security-Policy'));
    }

    public function testWithRedirection(): void
    {
        $listener = $this->buildSimpleListener(['default-src' => "default.example.org 'self'"], false, true, ['text/html']);
        $response = new RedirectResponse('/redirect');
        $event = $this->createResponseEventWithKernel(
            $this->kernel,
            Request::create('/'),
            true,
            $response
        );
        $listener->onKernelResponse($event);

        $this->assertNull($response->headers->get('Content-Security-Policy'));
    }

    public function testScript(): void
    {
        $script = "script.example.org 'self' 'unsafe-eval' 'strict-dynamic' 'unsafe-inline'";

        $listener = $this->buildSimpleListener(['script-src' => $script]);
        $response = $this->callListener($listener, '/', true);
        $this->assertSame(
            "script-src script.example.org 'self' 'unsafe-eval' 'strict-dynamic' 'unsafe-inline'",
            $response->headers->get('Content-Security-Policy')
        );
    }

    public function testObject(): void
    {
        $object = "object.example.org 'self'";

        $listener = $this->buildSimpleListener(['object-src' => $object]);
        $response = $this->callListener($listener, '/', true);
        $this->assertSame("object-src object.example.org 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testStyle(): void
    {
        $style = "style.example.org 'self'";

        $listener = $this->buildSimpleListener(['style-src' => $style]);
        $response = $this->callListener($listener, '/', true);
        $this->assertSame("style-src style.example.org 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testImg(): void
    {
        $img = "img.example.org 'self'";

        $listener = $this->buildSimpleListener(['img-src' => $img]);
        $response = $this->callListener($listener, '/', true);
        $this->assertSame("img-src img.example.org 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testMedia(): void
    {
        $media = "media.example.org 'self'";

        $listener = $this->buildSimpleListener(['media-src' => $media]);
        $response = $this->callListener($listener, '/', true);
        $this->assertSame("media-src media.example.org 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testFrame(): void
    {
        $frame = "frame.example.org 'self'";

        $listener = $this->buildSimpleListener(['frame-src' => $frame]);
        $response = $this->callListener($listener, '/', true);
        $this->assertSame("frame-src frame.example.org 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testFont(): void
    {
        $font = "font.example.org 'self'";

        $listener = $this->buildSimpleListener(['font-src' => $font]);
        $response = $this->callListener($listener, '/', true);
        $this->assertSame("font-src font.example.org 'self'", $response->headers->get('Content-Security-Policy'));
    }

    public function testConnect(): void
    {
        $connect = "connect.example.org 'self'";

        $listener = $this->buildSimpleListener(['connect-src' => $connect]);
        $response = $this->callListener($listener, '/', true);
        $this->assertSame(
            "connect-src connect.example.org 'self'",
            $response->headers->get('Content-Security-Policy')
        );
    }

    public function testReportUri(): void
    {
        $reportUri = 'http://example.org/CSPReport';

        $listener = $this->buildSimpleListener(['report-uri' => $reportUri]);
        $response = $this->callListener($listener, '/', true);
        $this->assertSame(
            'report-uri http://example.org/CSPReport',
            $response->headers->get('Content-Security-Policy')
        );
    }

    public function testEmpty(): void
    {
        $listener = $this->buildSimpleListener([]);
        $response = $this->callListener($listener, '/', true);
        $this->assertNull($response->headers->get('Content-Security-Policy'));
    }

    public function testAll(): void
    {
        $reportUri = 'http://example.org/CSPReport';

        $listener = $this->buildSimpleListener([
            'default-src' => "example.org 'self'",
            'script-src' => "script.example.org 'self'",
            'object-src' => "object.example.org 'self'",
            'style-src' => "style.example.org 'self'",
            'img-src' => "img.example.org 'self'",
            'media-src' => "media.example.org 'self'",
            'frame-src' => "frame.example.org 'self'",
            'font-src' => "font.example.org 'self'",
            'connect-src' => "connect.example.org 'self'",
            'report-uri' => $reportUri,
            'base-uri' => "base-uri.example.org 'self'",
            'child-src' => "child-src.example.org 'self'",
            'form-action' => "form-action.example.org 'self'",
            'frame-ancestors' => "frame-ancestors.example.org 'self'",
            'plugin-types' => 'application/shockwave-flash',
            'block-all-mixed-content' => true,
            'upgrade-insecure-requests' => true,
        ]);
        $response = $this->callListener($listener, '/', true);

        $header = $response->headers->get('Content-Security-Policy');

        $this->assertIsString($header);
        $this->assertStringContainsString("default-src example.org 'self'", $header, 'Header should contain default-src');
        $this->assertStringContainsString("script-src script.example.org 'self'", $header, 'Header should contain script-src');
        $this->assertStringContainsString("object-src object.example.org 'self'", $header, 'Header should contain object-src');
        $this->assertStringContainsString("style-src style.example.org 'self'", $header, 'Header should contain style-src');
        $this->assertStringContainsString("img-src img.example.org 'self'", $header, 'Header should contain img-src');
        $this->assertStringContainsString("media-src media.example.org 'self'", $header, 'Header should contain media-src');
        $this->assertStringContainsString("frame-src frame.example.org 'self'", $header, 'Header should contain frame-src');
        $this->assertStringContainsString("font-src font.example.org 'self'", $header, 'Header should contain font-src');
        $this->assertStringContainsString("connect-src connect.example.org 'self'", $header, 'Header should contain connect-src');
        $this->assertStringContainsString('report-uri http://example.org/CSPReport', $header, 'Header should contain report-uri');
        $this->assertStringContainsString("base-uri base-uri.example.org 'self'", $header, 'Header should contain base-uri');
        $this->assertStringContainsString("child-src child-src.example.org 'self'", $header, 'Header should contain child-src');
        $this->assertStringContainsString("form-action form-action.example.org 'self'", $header, 'Header should contain form-action');
        $this->assertStringContainsString("frame-ancestors frame-ancestors.example.org 'self'", $header, 'Header should contain frame-ancestors');
        $this->assertStringContainsString('plugin-types application/shockwave-flash', $header, 'Header should contain plugin-types');
        $this->assertStringContainsString('block-all-mixed-content', $header, 'Header should contain block-all-mixed-content');
        $this->assertStringContainsString('upgrade-insecure-requests', $header, 'Header should contain upgrade-insecure-requests');
    }

    public function testDelimiter(): void
    {
        $spec = 'example.org';
        $listener = $this->buildSimpleListener([
            'default-src' => "default.example.org 'self'",
            'script-src' => "script.example.org 'self'",
            'object-src' => "object.example.org 'self'",
            'style-src' => "style.example.org 'self'",
            'img-src' => "img.example.org 'self'",
            'media-src' => "media.example.org 'self'",
            'frame-src' => "frame.example.org 'self'",
            'font-src' => "font.example.org 'self'",
            'connect-src' => "connect.example.org 'self'",
        ]);
        $response = $this->callListener($listener, '/', true);

        $header = $response->headers->get('Content-Security-Policy');

        $this->assertSame(
            "default-src default.example.org 'self'; script-src script.example.org 'self'; ".
            "object-src object.example.org 'self'; style-src style.example.org 'self'; ".
            "img-src img.example.org 'self'; media-src media.example.org 'self'; ".
            "frame-src frame.example.org 'self'; font-src font.example.org 'self'; ".
            "connect-src connect.example.org 'self'",
            $header,
            'The header should contain all directives separated by a semicolon'
        );
    }

    public function testAvoidDuplicates(): void
    {
        $spec = 'example.org';
        $listener = $this->buildSimpleListener([
            'default-src' => $spec,
            'script-src' => $spec,
            'object-src' => $spec,
            'style-src' => $spec,
            'img-src' => $spec,
            'media-src' => $spec,
            'frame-src' => $spec,
            'font-src' => $spec,
            'connect-src' => $spec,
        ]);
        $response = $this->callListener($listener, '/', true);

        $header = $response->headers->get('Content-Security-Policy');

        $this->assertSame(
            'default-src example.org',
            $header,
            'Response should contain only the default as the others are equivalent'
        );
    }

    public function testVendorPrefixes(): void
    {
        $spec = 'example.org';
        $listener = $this->buildSimpleListener([
            'default-src' => $spec,
            'script-src' => $spec,
            'object-src' => $spec,
            'style-src' => $spec,
            'img-src' => $spec,
            'media-src' => $spec,
            'frame-src' => $spec,
            'font-src' => $spec,
            'connect-src' => $spec,
        ]);
        $response = $this->callListener($listener, '/', true);

        $this->assertSame(
            $response->headers->get('Content-Security-Policy'),
            $response->headers->get('X-Content-Security-Policy'),
            'Response should contain non-standard X-Content-Security-Policy header'
        );
    }

    public function testReportOnly(): void
    {
        $spec = 'example.org';
        $listener = $this->buildSimpleListener([
            'default-src' => $spec,
            'script-src' => $spec,
            'object-src' => $spec,
            'style-src' => $spec,
            'img-src' => $spec,
            'media-src' => $spec,
            'frame-src' => $spec,
            'font-src' => $spec,
            'connect-src' => $spec,
        ], true);
        $response = $this->callListener($listener, '/', true);

        $this->assertNull($response->headers->get('Content-Security-Policy'));
        $this->assertNotNull($response->headers->get('Content-Security-Policy-Report-Only'));
    }

    public function testNoCompatHeaders(): void
    {
        $spec = 'example.org';
        $listener = $this->buildSimpleListener([
            'default-src' => $spec,
            'script-src' => $spec,
            'object-src' => $spec,
            'style-src' => $spec,
            'img-src' => $spec,
            'media-src' => $spec,
            'frame-src' => $spec,
            'font-src' => $spec,
            'connect-src' => $spec,
        ], false, false);
        $response = $this->callListener($listener, '/', true);

        $this->assertNull($response->headers->get('X-Content-Security-Policy'));
        $this->assertNotNull($response->headers->get('Content-Security-Policy'));
    }

    public function testDirectiveSetUnset(): void
    {
        $directiveSet = new DirectiveSet(new PolicyManager());
        $directiveSet->setDirectives(['default-src' => 'foo']);
        $this->assertSame('default-src foo', $directiveSet->buildHeaderValue(new Request()));
        $directiveSet->setDirective('default-src', '');
        $this->assertSame('', $directiveSet->buildHeaderValue(new Request()));
    }

    public function testHeadersAreNotOverwrittenIfPresent(): void
    {
        // enforced listener does not overwrite header if present
        $listener = $this->buildSimpleListener(['default-src' => "default.example.org 'self'"]);
        $response = $this->callListener($listener, '/', true, 'text/html', [], 0, ['Content-Security-Policy' => "script-src 'nonce-Ij+dwUNY004wIigo1Mp19Q=='"]);
        $this->assertSame(
            "script-src 'nonce-Ij+dwUNY004wIigo1Mp19Q=='",
            $response->headers->get('Content-Security-Policy')
        );

        // enforced listener adds the enforced header if only report-only one is present
        $response = $this->callListener($listener, '/', true, 'text/html', [], 0, ['Content-Security-Policy-Report-Only' => "script-src 'nonce-Ij+dwUNY004wIigo1Mp19Q=='"]);
        $this->assertSame(
            "default-src default.example.org 'self'",
            $response->headers->get('Content-Security-Policy')
        );
        $this->assertSame(
            "script-src 'nonce-Ij+dwUNY004wIigo1Mp19Q=='",
            $response->headers->get('Content-Security-Policy-Report-Only')
        );

        // report only does not overwrite report-only header if present
        $listener = $this->buildSimpleListener(['default-src' => "default.example.org 'self'"], true);
        $response = $this->callListener($listener, '/', true, 'text/html', [], 0, ['Content-Security-Policy-Report-Only' => "script-src 'nonce-Ij+dwUNY004wIigo1Mp19Q=='"]);

        $this->assertSame(
            "script-src 'nonce-Ij+dwUNY004wIigo1Mp19Q=='",
            $response->headers->get('Content-Security-Policy-Report-Only')
        );

        // report only does add report-only header if only the enforced header is present
        $response = $this->callListener($listener, '/', true, 'text/html', [], 0, ['Content-Security-Policy' => "script-src 'nonce-Ij+dwUNY004wIigo1Mp19Q=='"]);

        $this->assertSame(
            "script-src 'nonce-Ij+dwUNY004wIigo1Mp19Q=='",
            $response->headers->get('Content-Security-Policy')
        );
        $this->assertSame(
            "default-src default.example.org 'self'",
            $response->headers->get('Content-Security-Policy-Report-Only')
        );
    }

    /**
     * @param array<string, string|true> $directives
     * @param list<string>               $contentTypes
     */
    private function buildSimpleListener(array $directives, bool $reportOnly = false, bool $compatHeaders = true, array $contentTypes = []): ContentSecurityPolicyListener
    {
        $directiveSet = new DirectiveSet(new PolicyManager());
        $directiveSet->setDirectives($directives);

        if ($reportOnly) {
            return new ContentSecurityPolicyListener($directiveSet, new DirectiveSet(new PolicyManager()), $this->nonceGenerator, $this->shaComputer, $compatHeaders, $contentTypes);
        }

        return new ContentSecurityPolicyListener(new DirectiveSet(new PolicyManager()), $directiveSet, $this->nonceGenerator, $this->shaComputer, $compatHeaders, $contentTypes);
    }

    /**
     * @param array{
     *  signatures?: array{
     *      script-src: list<string>
     *  },
     *  scripts?: list<string>,
     *  styles?: list<string>
     * } $digestData
     * @param array<string, string> $responseHeaders
     */
    private function callListener(ContentSecurityPolicyListener $listener, string $path, bool $mainReq, string $contentType = 'text/html', array $digestData = [], int $getNonce = 0, array $responseHeaders = []): Response
    {
        $request = Request::create($path);

        $event = $this->createRequestEventWithKernel(
            $this->kernel,
            $request,
            $mainReq
        );

        $listener->onKernelRequest($event);

        if (isset($digestData['scripts'])) {
            foreach ($digestData['scripts'] as $script) {
                $listener->addScript($script);
            }
        }
        if (isset($digestData['styles'])) {
            foreach ($digestData['styles'] as $style) {
                $listener->addStyle($style);
            }
        }

        if (isset($digestData['signatures'])) {
            foreach ($digestData['signatures'] as $type => $values) {
                foreach ($values as $value) {
                    $listener->addSha($type, $value);
                }
            }
        }

        for ($i = 0; $i < $getNonce; ++$i) {
            $listener->getNonce('script');
            $listener->getNonce('style');
        }

        $response = new Response();
        $response->headers->add(['content-type' => $contentType]);
        $response->headers->add($responseHeaders);

        $event = $this->createResponseEventWithKernel(
            $this->kernel,
            $request,
            $mainReq,
            $response
        );
        $listener->onKernelResponse($event);

        return $response;
    }
}
