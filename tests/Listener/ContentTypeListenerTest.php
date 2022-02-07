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
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class ContentTypeListenerTest extends ListenerTestCase
{
    public function testNoSniff(): void
    {
        $listener = new ContentTypeListener(true);
        $response = $this->callListener($listener, '/', true);
        $this->assertSame(
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

    private function callListener(ContentTypeListener $listener, string $path, bool $mainReq): Response
    {
        $request = Request::create($path);
        $response = new Response();

        $event = $this->createResponseEvent($request, $mainReq, $response);
        $listener->onKernelResponse($event);

        return $response;
    }
}
