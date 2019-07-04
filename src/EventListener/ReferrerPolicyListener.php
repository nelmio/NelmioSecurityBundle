<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\EventListener;

use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Referrer Policy Listener.
 *
 * @author Andrej Hudec <pulzarraider@gmail.com>
 */
class ReferrerPolicyListener
{
    private $policies;

    public function __construct(array $policies)
    {
        $this->policies = $policies;
    }

    public function onKernelResponse(FilterResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        $response = $e->getResponse();

        $response->headers->set('Referrer-Policy', implode(', ', $this->policies));
    }
}
