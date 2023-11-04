<?php

declare(strict_types=1);

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\EventListener;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

final class ForcedSslListener
{
    private ?int $hstsMaxAge;
    private bool $hstsSubdomains;
    private bool $hstsPreload;
    private ?string $allowList;
    private ?string $hosts;
    private int $redirectStatusCode;

    /**
     * @param list<string> $allowList
     * @param list<string> $hosts
     */
    public function __construct(
        ?int $hstsMaxAge,
        bool $hstsSubdomains,
        bool $hstsPreload = false,
        array $allowList = [],
        array $hosts = [],
        int $redirectStatusCode = 302
    ) {
        $this->hstsMaxAge = $hstsMaxAge;
        $this->hstsSubdomains = $hstsSubdomains;
        $this->hstsPreload = $hstsPreload;
        $this->allowList = [] !== $allowList ? '('.implode('|', $allowList).')' : null;
        $this->hosts = [] !== $hosts ? '('.implode('|', $hosts).')' : null;
        $this->redirectStatusCode = $redirectStatusCode;
    }

    public function onKernelRequest(RequestEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        $request = $e->getRequest();

        // skip SSL & non-GET/HEAD requests
        if ($request->isSecure() || !$request->isMethodSafe()) {
            return;
        }

        // skip allowed URLs
        if (null !== $this->allowList && 1 === preg_match('{'.$this->allowList.'}i', '' === $request->getPathInfo() ? '/' : $request->getPathInfo())) {
            return;
        }

        // skip non-listed hosts
        if (null !== $this->hosts && 1 !== preg_match('{'.$this->hosts.'}i', '' === $request->getHost() ? '/' : $request->getHost())) {
            return;
        }

        // redirect the rest to SSL
        $e->setResponse(new RedirectResponse('https://'.substr($request->getUri(), 7), $this->redirectStatusCode));
    }

    public function onKernelResponse(ResponseEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        // skip non-SSL requests as per the RFC
        // "An HSTS Host MUST NOT include the STS header field in HTTP responses conveyed over non-secure transport."
        $request = $e->getRequest();
        if (!$request->isSecure()) {
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
