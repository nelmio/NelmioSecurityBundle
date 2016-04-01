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
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;

class ContentSecurityPolicyListener extends AbstractContentTypeRestrictableListener
{
    protected $report;
    protected $enforce;
    protected $compatHeaders;
    protected $hosts;
    protected $nonce;
    protected $sha;
    protected $nonceGenerator;
    protected $shaComputer;

    public function __construct(DirectiveSet $report, DirectiveSet $enforce, NonceGenerator $nonceGenerator, ShaComputer $shaComputer, $compatHeaders = true, array $hosts = array(), array $contentTypes = array())
    {
        $this->report = $report;
        $this->enforce = $enforce;
        $this->compatHeaders = $compatHeaders;
        $this->hosts = $hosts;
        $this->contentTypes = $contentTypes;
        $this->nonceGenerator = $nonceGenerator;
        $this->shaComputer = $shaComputer;
    }

    public function onKernelRequest(GetResponseEvent $event)
    {
        if (!$event->isMasterRequest()) {
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

    public function getNonce()
    {
        if (null === $this->nonce) {
            $this->nonce = $this->nonceGenerator->generate();
        }

        return $this->nonce;
    }

    public function onKernelResponse(FilterResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        $response = $e->getResponse();

        if ($response->isRedirection()) {
            $this->nonce = null;
            $this->sha = null;

            return;
        }

        if ((empty($this->hosts) || in_array($e->getRequest()->getHost(), $this->hosts, true)) && $this->isContentTypeValid($response)) {
            $signatures = $this->sha;
            if ($this->nonce) {
                $signatures['script-src'][] = 'nonce-'.$this->nonce;
                $signatures['style-src'][] = 'nonce-'.$this->nonce;
            }

            $response->headers->add($this->buildHeaders($this->report, true, $this->compatHeaders, $signatures));
            $response->headers->add($this->buildHeaders($this->enforce, false, $this->compatHeaders, $signatures));
        }

        $this->nonce = null;
        $this->sha = null;
    }

    private function buildHeaders(DirectiveSet $directiveSet, $reportOnly, $compatHeaders, array $signatures = null)
    {
        // $signatures might be null if no KernelEvents::REQUEST has been triggered.
        // for instance if a security.authentication.failure has been dispatched
        if (!empty($signatures)) {
            $headerValue = $directiveSet->buildHeaderValueWithInlineSignatures($signatures);
        } else {
            $headerValue = $directiveSet->buildHeaderValue();
        }

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

    public static function getSubscribedEvents()
    {
        return array(
            KernelEvents::REQUEST => 'onKernelRequest',
            KernelEvents::RESPONSE => 'onKernelResponse',
        );
    }
}
