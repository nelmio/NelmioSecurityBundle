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
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * @final
 */
class ClickjackingListener extends AbstractContentTypeRestrictableListener
{
    private $paths;

    public function __construct(array $paths, array $contentTypes = [])
    {
        parent::__construct($contentTypes);
        $this->paths = $paths;
    }

    /**
     * @return array
     */
    public static function getSubscribedEvents()
    {
        return [KernelEvents::RESPONSE => 'onKernelResponse'];
    }

    public function onKernelResponse(ResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        if (!$this->isContentTypeValid($e->getResponse())) {
            return;
        }

        $response = $e->getResponse();

        if ($response->isRedirection()) {
            return;
        }

        $currentPath = $e->getRequest()->getRequestUri() ?: '/';

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
