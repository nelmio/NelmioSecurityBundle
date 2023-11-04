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
 * @author Andrej Hudec <pulzarraider@gmail.com>
 */
final class ReferrerPolicyListener
{
    /**
     * @var list<string>
     */
    private array $policies;

    /**
     * @param list<string> $policies
     */
    public function __construct(array $policies)
    {
        $this->policies = $policies;
    }

    public function onKernelResponse(ResponseEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        $response = $e->getResponse();

        $response->headers->set('Referrer-Policy', implode(', ', $this->policies));
    }
}
