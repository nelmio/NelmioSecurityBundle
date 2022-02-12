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

use Nelmio\SecurityBundle\ExternalRedirect\TargetValidator;
use Nelmio\SecurityBundle\ExternalRedirect\WhitelistBasedTargetValidator;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * @final
 */
class ExternalRedirectListener
{
    private $abort;
    private $override;
    private $forwardAs;
    private $targetValidator;
    private $logger;
    private $generator;

    /**
     * @param bool                  $abort           If true, the offending redirects are turned into 403 responses, can't be combined with $override
     * @param string                $override        Absolute path, complete URL or route name that must be used instead of the offending redirect's url
     * @param string                $forwardAs       Name of the route-/query string parameter the blocked url will be passed to destination location
     * @param mixed                 $targetValidator array of hosts to be allowed, or regex that matches allowed hosts, or implementation of TargetValidator
     * @param LoggerInterface       $logger          A logger, if it's present, detected offenses are logged at the warning level
     * @param UrlGeneratorInterface $generator       Router or equivalent that can generate a route, only if override is a route name
     */
    public function __construct($abort = true, $override = null, $forwardAs = null, $targetValidator = null, LoggerInterface $logger = null, UrlGeneratorInterface $generator = null)
    {
        if ($override && $abort) {
            throw new \LogicException('The ExternalRedirectListener can not abort *and* override redirects at the same time.');
        }
        $this->abort = $abort;
        $this->override = $override;
        $this->forwardAs = $forwardAs;

        if (is_string($targetValidator) || is_array($targetValidator)) {
            $targetValidator = new WhitelistBasedTargetValidator($targetValidator);
        } elseif ($targetValidator !== null && !$targetValidator instanceof TargetValidator) {
            throw new \LogicException('$targetValidator should be an array of hosts, a regular expression, or an implementation of TargetValidator.');
        }
        $this->targetValidator = $targetValidator;

        $this->logger = $logger;
        $this->generator = $generator;
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

        if (!$response->isRedirect()) {
            return;
        }

        $target = $response->headers->get('Location');
        if (!$this->isExternalRedirect($e->getRequest()->getUri(), $target)) {
            return;
        }

        if (null !== $this->targetValidator && $this->targetValidator->isTargetAllowed($target)) {
            return;
        }

        if ($this->logger) {
            $this->logger->warning('External redirect detected from '.$e->getRequest()->getUri().' to '.$response->headers->get('Location'));
        }

        if ($this->abort) {
            throw new HttpException(403, 'Invalid Redirect Given: '.$response->headers->get('Location'));
        }

        if ($this->override) {
            $parameters = array();
            if ($this->forwardAs) {
                $parameters[$this->forwardAs] = $response->headers->get('Location');
            }

            if (false === strpos($this->override, '/')) {
                if (!$this->generator) {
                    throw new \UnexpectedValueException('The listener needs a router/UrlGeneratorInterface object to override invalid redirects with routes');
                }
                $response->headers->set('Location', $this->generator->generate($this->override, $parameters));
            } else {
                $query = '';
                if (count($parameters) > 0) {
                    $query = (strpos($this->override, '?') === false) ? '?' : '&';
                    $query .= http_build_query($parameters, null, '&');
                }
                $response->headers->set('Location', $this->override.$query);
            }
        }
    }

    public function isExternalRedirect($source, $target)
    {
        // cleanup "\rhttp://foo.com/" and other null prefixeds to be scanned as valid internal redirect
        $target = trim($target);

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
