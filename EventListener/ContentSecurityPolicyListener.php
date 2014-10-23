<?php

namespace Nelmio\SecurityBundle\EventListener;

use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;

class ContentSecurityPolicyListener implements EventSubscriberInterface
{
    protected $report;
    protected $enforce;
    protected $compatHeaders;

    public function __construct(DirectiveSet $report, DirectiveSet $enforce, $compatHeaders = true)
    {
        $this->report = $report;
        $this->enforce = $enforce;
        $this->compatHeaders = $compatHeaders;
    }

    public function onKernelResponse(FilterResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        $response = $e->getResponse();
        $response->headers->add($this->buildHeaders($this->report, true, $this->compatHeaders));
        $response->headers->add($this->buildHeaders($this->enforce, false, $this->compatHeaders));
    }

    private function buildHeaders(DirectiveSet $directiveSet, $reportOnly, $compatHeaders)
    {
        $headerValue = $directiveSet->buildHeaderValue();
        if(!$headerValue) return array();

        $hn = function($name) use ($reportOnly) {
            return $name . ($reportOnly ? '-Report-Only' : '');
        };

        $headers = array(
            $hn('Content-Security-Policy') => $headerValue
        );

        if($compatHeaders) {
            $headers[$hn('X-Content-Security-Policy')] = $headerValue;
            $headers[$hn('X-Webkit-CSP')] = $headerValue;
        }

        return $headers;
    }

    private function buildHeaderName($baseName, $reportOnly) {
        return $baseName . ($reportOnly ? '-Report-Only' : '');
    }

    public static function getSubscribedEvents() {
        return array(KernelEvents::RESPONSE => 'onKernelResponse');
    }

    public static function fromConfig(array $config)
    {
        if(array_key_exists('report', $config) || array_key_exists('enforce', $config)){
            $enforce = DirectiveSet::fromConfig($config, 'enforce');
            $report = DirectiveSet::fromConfig($config, 'report');
        } else { // legacy config
            $directiveSet = DirectiveSet::fromLegacyConfig($config);

            if(!!$config['report_only']) {
                $enforce = new DirectiveSet();
                $report = $directiveSet;
            } else {
                $enforce = $directiveSet;
                $report = new DirectiveSet();
            }
        }

        return new self($report, $enforce, !!$config['compat_headers']);
    }
}