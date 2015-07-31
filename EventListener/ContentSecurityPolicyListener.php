<?php

namespace Nelmio\SecurityBundle\EventListener;

use Nelmio\SecurityBundle\ContentSecurityPolicy\NonceGenerator;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;

class ContentSecurityPolicyListener extends AbstractContentTypeRestrictableListener
{
    protected $report;
    protected $enforce;
    protected $compatHeaders;
    protected $hosts;

    /**
     * @var NonceGenerator
     */
    protected $nonceGenerator;

    public function __construct(DirectiveSet $report, DirectiveSet $enforce, $compatHeaders = true, array $hosts = array(), array $contentTypes = array())
    {
        $this->report = $report;
        $this->enforce = $enforce;
        $this->compatHeaders = $compatHeaders;
        $this->hosts = $hosts;
        $this->contentTypes = $contentTypes;
    }

    public function getReport()
    {
        return $this->report;
    }

    public function getEnforcement()
    {
        return $this->enforce;
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
        
        if ((empty($this->hosts) || in_array($e->getRequest()->getHost(), $this->hosts, true)) && $this->isContentTypeValid($response)) {
            $nonce = null;
            if ($this->nonceGenerator !== null) {
                $nonce = $this->nonceGenerator->generate();
            }

            $response->headers->add($this->buildHeaders($this->report, true, $this->compatHeaders, $nonce));
            $response->headers->add($this->buildHeaders($this->enforce, false, $this->compatHeaders, $nonce));
        }
    }

    private function buildHeaders(DirectiveSet $directiveSet, $reportOnly, $compatHeaders, $nonce)
    {
        if ($nonce !== null) {
            $headerValue = $directiveSet->buildHeaderValueWithNonce($nonce);
        } else {
            $headerValue = $directiveSet->buildHeaderValue();
        }

        if (!$headerValue) {
            return array();
        }

        $hn = function($name) use ($reportOnly) {
            return $name . ($reportOnly ? '-Report-Only' : '');
        };

        $headers = array(
            $hn('Content-Security-Policy') => $headerValue
        );

        if ($compatHeaders) {
            $headers[$hn('X-Content-Security-Policy')] = $headerValue;
        }

        return $headers;
    }

    /**
     * @param NonceGenerator $nonceGenerator
     *
     * @return $this
     */
    public function setNonceGenerator($nonceGenerator)
    {
        $this->nonceGenerator = $nonceGenerator;
        return $this;
    }

    public static function getSubscribedEvents()
    {
        return array(KernelEvents::RESPONSE => 'onKernelResponse');
    }
}
