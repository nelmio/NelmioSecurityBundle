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
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * @final
 */
class ClickjackingListener extends AbstractContentTypeRestrictableListener
{
    private $paths;
    private $hosts;

    public function __construct(array $paths, array $contentTypes = array(), array $hosts = array())
    {
        parent::__construct($contentTypes);
        $this->paths = $paths;
        $this->hosts = $hosts ? '('.implode('|', $hosts).')' : null;
    }

    public static function getSubscribedEvents()
    {
        return array(KernelEvents::RESPONSE => 'onKernelResponse');
    }

    /**
     * @param FilterResponseEvent|ResponseEvent $e
     */
    public function onKernelResponse($e)
    {
        // Compatibility with Symfony < 5 and Symfony >=5
        if (!$e instanceof FilterResponseEvent && !$e instanceof ResponseEvent) {
            throw new \InvalidArgumentException(\sprintf('Expected instance of type %s, %s given', \class_exists(ResponseEvent::class) ? ResponseEvent::class : FilterResponseEvent::class, \is_object($e) ? \get_class($e) : \gettype($e)));
        }

        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        if (!$this->isContentTypeValid($e->getResponse())) {
            return;
        }

        $request = $e->getRequest();
        $response = $e->getResponse();

        if ($response->isRedirection()) {
            return;
        }

        if ($response->headers->has('X-Frame-Options')) {
            // Do not overwrite an existing header
            return;
        }

        // skip non-listed hosts
        if (!empty($this->hosts) && !preg_match('{'.$this->hosts.'}i', $request->getHost() ?: '/')) {
            return;
        }

        $currentPath = $request->getRequestUri() ?: '/';

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
