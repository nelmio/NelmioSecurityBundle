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

use Nelmio\SecurityBundle\ContentSecurityPolicy\NonceGenerator;
use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputer;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;

/**
 * @final
 */
class ContentSecurityPolicyListener extends AbstractContentTypeRestrictableListener
{
    protected $report;
    protected $enforce;
    protected $compatHeaders;
    protected $hosts;
    protected $_nonce;
    protected $scriptNonce;
    protected $styleNonce;
    protected $sha;
    protected $nonceGenerator;
    protected $shaComputer;

    public function __construct(DirectiveSet $report, DirectiveSet $enforce, NonceGenerator $nonceGenerator, ShaComputer $shaComputer, $compatHeaders = true, array $hosts = array(), array $contentTypes = array())
    {
        parent::__construct($contentTypes);
        $this->report = $report;
        $this->enforce = $enforce;
        $this->compatHeaders = $compatHeaders;
        $this->hosts = $hosts;
        $this->nonceGenerator = $nonceGenerator;
        $this->shaComputer = $shaComputer;
    }

    /**
     * @param GetResponseEvent|RequestEvent $e
     */
    public function onKernelRequest($e)
    {
        // Compatibility with Symfony < 5 and Symfony >=5
        if (!$e instanceof GetResponseEvent && !$e instanceof RequestEvent) {
            throw new \InvalidArgumentException(\sprintf('Expected instance of type %s, %s given', \class_exists(RequestEvent::class) ? RequestEvent::class : GetResponseEvent::class, \is_object($e) ? \get_class($e) : \gettype($e)));
        }

        if ($e->getRequestType() !== HttpKernelInterface::MASTER_REQUEST) {
            return;
        }

        $this->sha = array();
    }

    public function addSha($directive, $sha)
    {
        if (null === $this->sha) {
            // We're not in a request context, probably in a worker
            // let's disable it to avoid memory leak
            return;
        }

        $this->sha[$directive][] = $sha;
    }

    public function addScript($html)
    {
        if (null === $this->sha) {
            // We're not in a request context, probably in a worker
            // let's disable it to avoid memory leak
            return;
        }

        $this->sha['script-src'][] = $this->shaComputer->computeForScript($html);
    }

    public function addStyle($html)
    {
        if (null === $this->sha) {
            // We're not in a request context, probably in a worker
            // let's disable it to avoid memory leak
            return;
        }

        $this->sha['style-src'][] = $this->shaComputer->computeForStyle($html);
    }

    public function getReport()
    {
        return $this->report;
    }

    public function getEnforcement()
    {
        return $this->enforce;
    }

    public function getNonce($usage = null)
    {
        $nonce = $this->doGetNonce();

        if ($usage === null) {
            @trigger_error('Retrieving a nonce without a usage is deprecated since version 2.4, and will be removed in version 3', E_USER_DEPRECATED);

            $this->scriptNonce = $nonce;
            $this->styleNonce = $nonce;
        } elseif ($usage === 'script') {
            $this->scriptNonce = $nonce;
        } elseif ($usage === 'style') {
            $this->styleNonce = $nonce;
        } else {
            throw new \InvalidArgumentException('Invalid usage provided');
        }

        return $nonce;
    }

    private function doGetNonce() {
        if (null === $this->_nonce) {
            $this->_nonce = $this->nonceGenerator->generate();
        }

        return $this->_nonce;
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

        $request = $e->getRequest();
        $response = $e->getResponse();

        if ($response->isRedirection()) {
            $this->_nonce = null;
            $this->styleNonce = null;
            $this->scriptNonce = null;
            $this->sha = null;

            return;
        }

        if ((empty($this->hosts) || in_array($e->getRequest()->getHost(), $this->hosts, true)) && $this->isContentTypeValid($response)) {
            $signatures = $this->sha;
            if ($this->scriptNonce) {
                $signatures['script-src'][] = 'nonce-'.$this->scriptNonce;
            }
            if ($this->styleNonce) {
                $signatures['style-src'][] = 'nonce-'.$this->styleNonce;
            }

            $response->headers->add($this->buildHeaders($request, $this->report, true, $this->compatHeaders, $signatures));
            $response->headers->add($this->buildHeaders($request, $this->enforce, false, $this->compatHeaders, $signatures));
        }

        $this->_nonce = null;
        $this->styleNonce = null;
        $this->scriptNonce = null;
        $this->sha = null;
    }

    private function buildHeaders(Request $request, DirectiveSet $directiveSet, $reportOnly, $compatHeaders, array $signatures = null)
    {
        // $signatures might be null if no KernelEvents::REQUEST has been triggered.
        // for instance if a security.authentication.failure has been dispatched
        $headerValue = $directiveSet->buildHeaderValue($request, $signatures);

        if (!$headerValue) {
            return array();
        }

        $hn = function ($name) use ($reportOnly) {
            return $name.($reportOnly ? '-Report-Only' : '');
        };

        $headers = array(
            $hn('Content-Security-Policy') => $headerValue,
        );

        if ($compatHeaders) {
            $headers[$hn('X-Content-Security-Policy')] = $headerValue;
        }

        return $headers;
    }

    /**
     * @return array
     */
    public static function getSubscribedEvents()
    {
        return array(
            KernelEvents::REQUEST => array('onKernelRequest', 512),
            KernelEvents::RESPONSE => 'onKernelResponse',
        );
    }
}
