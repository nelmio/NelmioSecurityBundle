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

use Nelmio\SecurityBundle\EventListener\ClickjackingListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ClickjackingListenerTest extends \PHPUnit\Framework\TestCase
{
    private $kernel;
    private $listener;

    protected function setUp(): void
    {
        $this->kernel = $this->getMockBuilder(HttpKernelInterface::class)->getMock();
        $this->listener = new ClickjackingListener([
            '^/frames/' => ['header' => 'ALLOW'],
            '/frames/' => ['header' => 'SAMEORIGIN'],
            '^.*\?[^\?]*foo=bar' => ['header' => 'ALLOW'],
            '/this/allow' => ['header' => 'ALLOW-FROM http://biz.domain.com'],
            '^/.*' => ['header' => 'DENY'],
            '.*' => ['header' => 'ALLOW'],
        ]);
    }

    /**
     * @dataProvider provideClickjackingMatches
     */
    public function testClickjackingMatches($path, $result)
    {
        $response = $this->callListener($this->listener, $path, true);
        $this->assertEquals($result, $response->headers->get('X-Frame-Options'));
    }

    public function provideClickjackingMatches()
    {
        return [
            ['', 'DENY'],
            ['/', 'DENY'],
            ['/test', 'DENY'],
            ['/path?test&foo=bar&another', null],
            ['/path?foo=bar', null],
            ['/frames/foo', null],
            ['/this/allow', 'ALLOW-FROM http://biz.domain.com'],
            ['/sub/frames/foo', 'SAMEORIGIN'],
        ];
    }

    public function testClickjackingSkipsSubReqs()
    {
        $response = $this->callListener($this->listener, '/', false);
        $this->assertEquals(null, $response->headers->get('X-Frame-Options'));
    }

    protected function callListener($listener, $path, $masterReq, $contentType = 'text/html')
    {
        $request = Request::create($path);
        $response = new Response();
        $response->headers->add(['content-type' => $contentType]);

        $event = new ResponseEvent($this->kernel, $request, $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST, $response);
        $listener->onKernelResponse($event);

        return $response;
    }

    /**
     * @dataProvider provideContentTypeForRestrictions
     */
    public function testClickjackingWithContentTypes($contentType, $result)
    {
        $this->listener = new ClickjackingListener([
            '^/frames/' => ['header' => 'ALLOW'],
            '/frames/' => ['header' => 'SAMEORIGIN'],
            '^/.*' => ['header' => 'DENY'],
            '.*' => ['header' => 'ALLOW'],
        ], ['text/html']);

        $response = $this->callListener($this->listener, '/', true, $contentType);
        $this->assertEquals($result, $response->headers->get('X-Frame-Options'));
    }

    public function provideContentTypeForRestrictions()
    {
        return [
            ['application/json', null],
            ['text/html', 'DENY'],
        ];
    }
}
