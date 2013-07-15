<?php

namespace Nelmio\SecurityBundle\EventListener;

use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ContentSecurityPolicyListener
{
    protected $default;
    protected $script;
    protected $object;
    protected $img;
    protected $media;
    protected $frame;
    protected $font;
    protected $connect;
    protected $style;
    protected $reportUri;

    public function __construct(
        $default = '',
        $script = '',
        $object = '',
        $style = '',
        $img = '',
        $media = '',
        $frame = '',
        $font = '',
        $connect = '',
        $reportUri = '',
        $reportOnly = false
    ) {
        $this->default    = $default;
        $this->script     = $script;
        $this->object     = $object;
        $this->style      = $style;
        $this->img        = $img;
        $this->media      = $media;
        $this->frame      = $frame;
        $this->font       = $font;
        $this->connect    = $connect;
        $this->reportUri  = $reportUri;
        $this->reportOnly = $reportOnly;
    }

    public function onKernelResponse(FilterResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        $response = $e->getResponse();

        $policy = array();

        if ($this->default) {
            $policy[] = 'default-src ' . $this->default;
        }

        if ($this->script) {
            $policy[] = 'script-src ' . $this->script;
        }

        if ($this->object) {
            $policy[] = 'object-src ' . $this->object;
        }

        if ($this->style) {
            $policy[] = 'style-src ' . $this->style;
        }

        if ($this->img) {
            $policy[] = 'img-src ' . $this->img;
        }

        if ($this->media) {
            $policy[] = 'media-src ' . $this->media;
        }

        if ($this->frame) {
            $policy[] = 'frame-src ' . $this->frame;
        }

        if ($this->font) {
            $policy[] = 'font-src ' . $this->font;
        }

        if ($this->connect) {
            $policy[] = 'connect-src ' . $this->connect;
        }

        if ($this->reportUri) {
            $policy[] = 'report-uri ' . $this->reportUri;
        }

        if ($policy) {
            $value = join('; ', $policy);

            $key       = 'Content-Security-Policy';
            $keyX      = 'X-Content-Security-Policy';
            $keyWebkit = 'X-Webkit-CSP';

            if ($this->reportOnly) {
                $key .= '-Report-Only';
                $keyX .= '-Report-Only';
                $keyWebkit .= '-Report-Only';
            }

            $response->headers->add(
                array(
                    $key       => $value,
                    $keyX      => $value,
                    $keyWebkit => $value
                )
            );
        }
    }
}