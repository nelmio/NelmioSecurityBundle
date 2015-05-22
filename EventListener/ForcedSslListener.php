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

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class ForcedSslListener
{
    private $hstsMaxAge;
    private $hstsSubdomains;
    private $hstsPreload;
    private $whitelist;

    public function __construct($hstsMaxAge, $hstsSubdomains, $hstsPreload = false, array $whitelist = array())
    {
        $this->hstsMaxAge = $hstsMaxAge;
        $this->hstsSubdomains = $hstsSubdomains;
        $this->hstsPreload = $hstsPreload;
        $this->whitelist = $whitelist ? '('.implode('|', $whitelist).')' : null;
    }

    public function onKernelRequest(GetResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        $request = $e->getRequest();

        // skip SSL & non-GET/HEAD requests
        if ($request->isSecure() || !$request->isMethodSafe()) {
            return;
        }

        // skip whitelisted URLs
        if ($this->whitelist && preg_match('{'.$this->whitelist.'}i', $request->getPathInfo() ?: '/')) {
            return;
        }

        // redirect the rest to SSL
        $e->setResponse(new RedirectResponse('https://'.substr($request->getUri(), 7)));
    }

    public function onKernelResponse(FilterResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        $response = $e->getResponse();

        if (!$response->headers->has('Strict-Transport-Security')) {
            $header = 'max-age='.$this->hstsMaxAge;
            $header .= ($this->hstsSubdomains ? '; includeSubDomains' : '');
            $header .= ($this->hstsPreload ? '; preload' : '');
            $response->headers->set('Strict-Transport-Security', $header);
        }
    }
}
