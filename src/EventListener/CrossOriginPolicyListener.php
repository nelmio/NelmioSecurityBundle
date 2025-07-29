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

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 */
final class CrossOriginPolicyListener
{
    private string $coep;
    private string $coop;
    private string $corp;

    public function __construct(string $coep, string $coop, string $corp)
    {
        $this->coep = $coep;
        $this->coop = $coop;
        $this->corp = $corp;
    }

    public function onKernelResponse(ResponseEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        $response = $e->getResponse();

        $response->headers->set('Cross-Origin-Embedder-Policy', $this->coep);
        $response->headers->set('Cross-Origin-Opener-Policy', $this->coop);
        $response->headers->set('Cross-Origin-Resource-Policy', $this->corp);
    }
}
