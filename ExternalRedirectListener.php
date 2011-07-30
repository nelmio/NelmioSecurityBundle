<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle;

use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\Log\LoggerInterface;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class ExternalRedirectListener
{
    private $abort;
    private $override;
    private $logger;
    private $generator;

    public function __construct($abort = true, $override = null, LoggerInterface $logger = null, UrlGeneratorInterface $generator = null)
    {
        if ($override && $abort) {
            throw new \LogicException('The ExternalRedirectListener can not abort *and* override redirects at the same time.');
        }
        $this->abort = $abort;
        $this->override = $override;
        $this->logger = $logger;
        $this->generator = $generator;
    }

    public function onKernelResponse(FilterResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        $response = $e->getResponse();

        if (!$response->isRedirect()) {
            return;
        }

        if (!$this->isExternalRedirect($e->getRequest()->getUri(), $response->headers->get('Location'))) {
            return;
        }

        if ($this->logger) {
            $this->logger->warn('External redirect detected from '.$e->getRequest()->getUri().' to '.$response->headers->get('Location'));
        }

        if ($this->abort) {
            throw new HttpException(403, 'Invalid Redirect Given: '.$response->headers->get('Location'));
        }

        if ($this->override) {
            if (false === strpos($this->override, '/')) {
                if (!$this->generator) {
                    throw new \UnexpectedValueException('The listener needs a router/UrlGeneratorInterface object to override invalid redirects with routes');
                }
                $response->headers->set('Location', $this->generator->generate($this->override));
            } else {
                $response->headers->set('Location', $this->override);
            }
        }
    }

    public function isExternalRedirect($source, $target)
    {
        // handle protocol-relative URLs that parse_url() doesn't like
        if (substr($target, 0, 2) === '//') {
            $target = 'proto:'.$target;
        }

        $target = parse_url($target);
        if (!isset($target['host'])) {
            return false;
        }

        $source = parse_url($source);
        if (!isset($source['host'])) {
            throw new \LogicException('The source url must include a host name.');
        }

        return $source['host'] !== $target['host'];
    }
}
