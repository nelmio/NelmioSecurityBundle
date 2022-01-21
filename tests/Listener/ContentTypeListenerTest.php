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

use Nelmio\SecurityBundle\EventListener\ContentTypeListener;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ContentTypeListenerTest extends TestCase
{
    /**
     * @var Stub&HttpKernelInterface
     */
    private $kernel;

    protected function setUp(): void
    {
        $this->kernel = $this->createStub(HttpKernelInterface::class);
    }

    public function testNoSniff(): void
    {
        $listener = new ContentTypeListener(true);
        $response = $this->callListener($listener, '/', true);
        $this->assertEquals(
            'nosniff',
            $response->headers->get('X-Content-Type-Options'),
            'X-Content-Type-Options header should be present'
        );
    }

    public function testEmpty(): void
    {
        $listener = new ContentTypeListener(false);
        $response = $this->callListener($listener, '/', true);
        $this->assertNull(
            $response->headers->get('X-Content-Type-Options'),
            'X-Content-Type-Options header should not be present'
        );
    }

    protected function callListener(ContentTypeListener $listener, string $path, bool $masterReq): Response
    {
        $request = Request::create($path);
        $response = new Response();

        $event = new ResponseEvent($this->kernel, $request, $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST, $response);
        $listener->onKernelResponse($event);

        return $response;
    }
}
