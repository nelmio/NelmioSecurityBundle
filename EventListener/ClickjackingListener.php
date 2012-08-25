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

class ClickjackingListener
{
    private $paths;

    public function __construct($paths)
    {
        $this->paths = $paths;
    }

    public function onKernelResponse(FilterResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        $response = $e->getResponse();
        $currentPath = $e->getRequest()->getPathInfo() ?: '/';

        foreach ($this->paths as $path => $options) {
            if (preg_match('{'.$path.'}i', $currentPath)) {
                if ('ALLOW' === $options['header']) {
                    $response->headers->remove('X-Frame-Options');
                } else {
                    $response->headers->set('X-Frame-Options', $options['header']);
                }

                return;
            }
        }
    }
}
