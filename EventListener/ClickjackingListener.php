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
use Symfony\Component\HttpKernel\KernelEvents;

class ClickjackingListener extends AbstractContentTypeRestrictableListener
{
    private $rules;

    public function __construct($rules, $contentTypes = array())
    {
        $this->rules = $rules;
        $this->contentTypes = $contentTypes;
    }

    public static function getSubscribedEvents()
    {
        return array(KernelEvents::RESPONSE => 'onKernelResponse');
    }

    public function onKernelResponse(FilterResponseEvent $e)
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

        $currentPath = $e->getRequest()->getPathInfo() ?: '/';

        foreach ($this->rules as $rule) {
            if (preg_match('{'.$rule['path'].'}i', $currentPath)) {
                if ('ALLOW' === $rule['header']) {
                    $response->headers->remove('X-Frame-Options');
                } else {
                    $response->headers->set('X-Frame-Options', $rule['header']);
                }

                return;
            }
        }
    }
}
