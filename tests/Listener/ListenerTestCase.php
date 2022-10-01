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

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

abstract class ListenerTestCase extends TestCase
{
    protected function createRequestEventWithKernel(
        HttpKernelInterface $httpKernel,
        Request $request,
        bool $mainRequest
    ): RequestEvent {
        return new RequestEvent(
            $httpKernel,
            $request,
            $this->getRequestType($mainRequest),
        );
    }

    protected function createRequestEvent(
        Request $request,
        bool $mainRequest
    ): RequestEvent {
        return new RequestEvent(
            $this->createStub(HttpKernelInterface::class),
            $request,
            $this->getRequestType($mainRequest),
        );
    }

    protected function createResponseEventWithKernel(
        HttpKernelInterface $httpKernel,
        Request $request,
        bool $mainRequest,
        Response $response
    ): ResponseEvent {
        return new ResponseEvent(
            $httpKernel,
            $request,
            $this->getRequestType($mainRequest),
            $response
        );
    }

    protected function createResponseEvent(
        Request $request,
        bool $mainRequest,
        Response $response
    ): ResponseEvent {
        return new ResponseEvent(
            $this->createStub(HttpKernelInterface::class),
            $request,
            $this->getRequestType($mainRequest),
            $response
        );
    }

    private function getRequestType(bool $mainRequest): int
    {
        if (!$mainRequest) {
            return HttpKernelInterface::SUB_REQUEST;
        }

        return \defined(HttpKernelInterface::class.'::MAIN_REQUEST')
            ? HttpKernelInterface::MAIN_REQUEST
            : HttpKernelInterface::MASTER_REQUEST
        ;
    }
}
