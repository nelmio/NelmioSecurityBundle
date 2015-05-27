<?php

namespace Nelmio\SecurityBundle\EventListener;

use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ContentTypeListener
{
    protected $nosniff;

    public function __construct($nosniff)
    {
        $this->nosniff = $nosniff;
    }

    public function onKernelResponse(FilterResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        if (!$this->nosniff) {
            return;
        }

        $response = $e->getResponse();

        if ($response->isRedirection()) {
            return;
        }

        $response->headers->add(array('X-Content-Type-Options' => 'nosniff'));
    }
}
