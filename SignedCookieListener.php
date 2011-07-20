<?php

namespace Nelmio\SecurityBundle;

use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;

class SignedCookieListener
{
    private $signer;
    private $signedCookieNames;

    public function __construct(Signer $signer, $signedCookieNames)
    {
        $this->signer = $signer;
        $this->signedCookieNames = $signedCookieNames;
    }

    public function onKernelRequest(GetResponseEvent $e)
    {
        $request = $e->getRequest();

        foreach ($this->signedCookieNames as $name) {
            if ($request->cookies->has($name)) {
                $cookie = $request->cookies->get($name);
                if ($this->signer->verifySignedValue($cookie)) {
                    $request->cookies->set($name, $this->signer->getVerifiedRawValue($cookie));
                } else {
                    $request->cookies->remove($name);
                }
            }
        }
    }

    public function onKernelResponse(FilterResponseEvent $e)
    {
        $response = $e->getResponse();

        foreach ($this->signedCookieNames as $name) {
            if ($response->headers->hasCookie($name)) {
                $cookie = $response->headers->getCookie($name);
                $signedCookie = new Cookie($name, $this->signer->getSignedValue($cookie->getValue()));
                $response->headers->setCookie($signedCookie);
            }
        }
    }
}
