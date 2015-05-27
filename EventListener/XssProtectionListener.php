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
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\KernelEvents;

class XssProtectionListener implements EventSubscriberInterface
{
    private $enabled;
    private $modeBlock;

    public function __construct($enabled, $modeBlock)
    {
        $this->enabled = $enabled;
        $this->modeBlock = $modeBlock;
    }

    public function onKernelResponse(FilterResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        $response = $e->getResponse();

        if ($response->isRedirection()) {
            return;
        }

        if ($this->enabled) {
            if ($this->modeBlock) {
                $value = '1; mode=block';
            } else {
                $value = '1';
            }
        } else {
            $value = '0';
        }

        $response->headers->set('X-XSS-Protection', $value);
    }

    public static function getSubscribedEvents()
    {
        return array(KernelEvents::RESPONSE => 'onKernelResponse');
    }

    public static function fromConfig(array $config)
    {
        $enabled = $config['enabled'];
        $modeBlock = $config['mode_block'];

        return new self($enabled, $modeBlock);
    }
}
