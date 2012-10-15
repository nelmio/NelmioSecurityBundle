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
use Symfony\Component\HttpKernel\Log\LoggerInterface;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class ExternalRedirectListener
{
    private $abort;
    private $override;
    private $overrideurlparametername;
    private $whitelist;
    private $logger;
    private $generator;

    /**
     * @param Boolean               $abort     If true, the offending redirects are turned into 403 responses, can't be combined with $override
     * @param string                $override  Absolute path, complete URL or route name that must be used instead of the offending redirect's url
     * @param string                $overrideurlparametername  Name of the route-/query string parameter the blocked url will be passed to destination location
     * @param mixed                 $whitelist array of hosts to be whitelisted, or regex that matches whitelisted hosts
     * @param LoggerInterface       $logger    A logger, if it's present, detected offenses are logged at the warning level
     * @param UrlGeneratorInterface $generator Router or equivalent that can generate a route, only if override is a route name
     */
    public function __construct($abort = true, $override = null, $overrideurlparametername=null, $whitelist = null, LoggerInterface $logger = null, UrlGeneratorInterface $generator = null)
    {
        if ($override && $abort) {
            throw new \LogicException('The ExternalRedirectListener can not abort *and* override redirects at the same time.');
        }
        $this->abort = $abort;
        $this->override = $override;
        $this->overrideurlparametername = $overrideurlparametername;
        if (is_array($whitelist)) {
            if ($whitelist) {
                $whitelist = array_map(function($el) {
                    return ltrim($el, '.');
                }, $whitelist);
                $whitelist = array_map('preg_quote', $whitelist);
                $whitelist = '(?:.*\.'.implode('|.*\.', $whitelist).'|'.implode('|', $whitelist).')';
            } else {
                $whitelist = null;
            }
        }
        $this->whitelist = $whitelist;
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

        $target = $response->headers->get('Location');
        if (!$this->isExternalRedirect($e->getRequest()->getUri(), $target)) {
            return;
        }

        if ($this->whitelist && preg_match('{^'.$this->whitelist.'$}i', parse_url($target, PHP_URL_HOST))) {
            return;
        }

        if ($this->logger) {
            $this->logger->warn('External redirect detected from '.$e->getRequest()->getUri().' to '.$response->headers->get('Location'));
        }

        if ($this->abort) {
            throw new HttpException(403, 'Invalid Redirect Given: '.$response->headers->get('Location'));
        }

        if ($this->override) {
            $parameters = array();
            if ($this->overrideurlparametername) {
                $parameters[$this->overrideurlparametername] = $response->headers->get('Location');
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
