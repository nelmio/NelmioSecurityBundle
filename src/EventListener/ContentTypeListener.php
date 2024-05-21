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

namespace Nelmio\SecurityBundle\EventListener;

use Symfony\Component\HttpKernel\Event\ResponseEvent;

final class ContentTypeListener
{
    private bool $nosniff;

    public function __construct(bool $nosniff)
    {
        $this->nosniff = $nosniff;
    }

    public function onKernelResponse(ResponseEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        if (!$this->nosniff) {
            return;
        }

        $response = $e->getResponse();

        if ($response->isRedirection()) {
            return;
        }

        $response->headers->add(['X-Content-Type-Options' => 'nosniff']);
    }
}
