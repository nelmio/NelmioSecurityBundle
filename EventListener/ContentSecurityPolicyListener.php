<?php

namespace Nelmio\SecurityBundle\EventListener;

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
            $response->headers->add($this->buildHeaders($this->report, true, $this->compatHeaders));
            $response->headers->add($this->buildHeaders($this->enforce, false, $this->compatHeaders));
        }
    }

    private function buildHeaders(DirectiveSet $directiveSet, $reportOnly, $compatHeaders)
    {
        $headerValue = $directiveSet->buildHeaderValue();
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

    public static function getSubscribedEvents()
    {
        return array(KernelEvents::RESPONSE => 'onKernelResponse');
    }

    public static function fromConfig(array $config)
    {
        if (array_key_exists('report', $config) || array_key_exists('enforce', $config)) {
            $enforce = DirectiveSet::fromConfig($config, 'enforce');
            $report = DirectiveSet::fromConfig($config, 'report');
        } else {
            // legacy config
            $directiveSet = DirectiveSet::fromLegacyConfig($config);

            if ((bool) $config['report_only']) {
                $enforce = new DirectiveSet();
                $report = $directiveSet;
            } else {
                $enforce = $directiveSet;
                $report = new DirectiveSet();
            }
        }

        return new self($report, $enforce, (bool) $config['compat_headers'], $config['hosts'], $config['content_types']);
    }
}
