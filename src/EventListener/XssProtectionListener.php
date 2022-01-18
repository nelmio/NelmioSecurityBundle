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
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * @final
 */
class XssProtectionListener implements EventSubscriberInterface
{
    private $enabled;
    private $modeBlock;
    private $reportUri;

    public function __construct($enabled, $modeBlock, $reportUri = null)
    {
        $this->enabled = $enabled;
        $this->modeBlock = $modeBlock;
        $this->reportUri = $reportUri;
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

        $response = $e->getResponse();

        if ($response->isRedirection()) {
            return;
        }

        $value = '0';
        if ($this->enabled) {
            $value = '1';

            if ($this->modeBlock) {
                $value .= '; mode=block';
            }

            if ($this->reportUri) {
                $value .= '; report=' . $this->reportUri;
            }
        }

        $response->headers->set('X-XSS-Protection', $value);
    }

    /**
     * @return array
     */
    public static function getSubscribedEvents()
    {
        return array(KernelEvents::RESPONSE => 'onKernelResponse');
    }

    public static function fromConfig(array $config)
    {
        $enabled = $config['enabled'];
        $modeBlock = $config['mode_block'];
        $reportUri = $config['report_uri'];

        return new self($enabled, $modeBlock, $reportUri);
    }
}
