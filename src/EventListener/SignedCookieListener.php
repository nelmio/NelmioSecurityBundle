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

use Nelmio\SecurityBundle\Signer\SignerInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

final class SignedCookieListener
{
    private SignerInterface $signer;

    /**
     * @var list<string>|true
     */
    private $signedCookieNames;

    /**
     * @param list<string> $signedCookieNames
     */
    public function __construct(SignerInterface $signer, array $signedCookieNames)
    {
        $this->signer = $signer;
        if (\in_array('*', $signedCookieNames, true)) {
            $this->signedCookieNames = true;
        } else {
            $this->signedCookieNames = $signedCookieNames;
        }
    }

    public function onKernelRequest(RequestEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        $request = $e->getRequest();

        $names = true === $this->signedCookieNames ? $request->cookies->keys() : $this->signedCookieNames;
        foreach ($names as $name) {
            if ($request->cookies->has($name)) {
                $cookie = $request->cookies->get($name, '');
                if ($this->signer->verifySignedValue($cookie)) {
                    $request->cookies->set($name, $this->signer->getVerifiedRawValue($cookie));
                } else {
                    $request->cookies->remove($name);
                }
            }
        }
    }

    public function onKernelResponse(ResponseEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        $response = $e->getResponse();

        foreach ($response->headers->getCookies() as $cookie) {
            if (true === $this->signedCookieNames || \in_array($cookie->getName(), $this->signedCookieNames, true)) {
                $response->headers->removeCookie($cookie->getName(), $cookie->getPath(), $cookie->getDomain());
                $signedCookie = new Cookie(
                    $cookie->getName(),
                    $this->signer->getSignedValue((string) $cookie->getValue()),
                    $cookie->getExpiresTime(),
                    $cookie->getPath(),
                    $cookie->getDomain(),
                    $cookie->isSecure(),
                    $cookie->isHttpOnly(),
                    $cookie->isRaw(),
                    $cookie->getSameSite()
                );
                $response->headers->setCookie($signedCookie);
            }
        }
    }
}
