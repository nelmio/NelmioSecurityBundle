<?php

namespace Nelmio\SecurityBundle\EventListener;

use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ContentSecurityPolicyListener
{
    protected $keywords = array('self', 'none', 'unsafe-inline', 'unsafe-eval');

    protected $default = array();
    protected $script = array();
    protected $object = array();
    protected $img = array();
    protected $media = array();
    protected $frame = array();
    protected $font = array();
    protected $connect = array();
    protected $style = array();

    public function __construct(
        array $default = array(),
        array $script = array(),
        array $object = array(),
        array $img = array(),
        array $media = array(),
        array $frame = array(),
        array $font = array(),
        array $connect = array(),
        array $style = array(),
        $reportUri = ''
    ) {
        $this->default = $default;
        $this->script  = $script;
        $this->object  = $object;
        $this->img     = $img;
        $this->media   = $media;
        $this->frame   = $frame;
        $this->font    = $font;
        $this->connect = $connect;
        $this->style   = $style;
    }

    public function onKernelResponse(FilterResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        $response = $e->getResponse();

        $policy = array();

        if ($this->default) {
            $policy[] = 'default-src ' . join(' ', $this->quoteKeywords($this->default));
        }

        if ($policy) {
            $response->headers->add(array('Content-Security-Policy' => join('; ', $policy)));
        }
    }

    protected function quoteKeywords(array $input)
    {
        $keywords = $this->keywords;

        return array_map(
            function ($keyword) use ($keywords) {
                if (in_array($keyword, $keywords)) {
                    return sprintf("'%s'", $keyword);
                }

                return $keyword;
            },
            $input
        );
    }

}