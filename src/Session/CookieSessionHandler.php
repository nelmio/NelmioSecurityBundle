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

namespace Nelmio\SecurityBundle\Session;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * @final
 */
class CookieSessionHandler implements \SessionHandlerInterface
{
    private ?Request $request = null;
    private string $cookieName;
    private int $lifetime;
    private string $path;
    private ?string $domain;
    private bool $secure;
    private bool $httpOnly;
    /**
     * @var Cookie|bool|null
     */
    private $cookie = false;
    private ?LoggerInterface $logger;

    public function __construct(
        string $cookieName,
        int $lifetime = 0,
        string $path = '/',
        ?string $domain = null,
        bool $secure = false,
        bool $httpOnly = true,
        ?LoggerInterface $logger = null
    ) {
        $this->cookieName = $cookieName;
        $this->path = $path;
        $this->domain = $domain;
        $this->lifetime = $lifetime;
        $this->secure = $secure;
        $this->httpOnly = $httpOnly;
        $this->logger = $logger;
    }

    public function onKernelResponse(ResponseEvent $e): void
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        if ($this->logger) {
            $this->logger->debug('CookieSessionHandler::onKernelResponse - Get the Response object');
        }

        $this->request->getSession()->save();

        if (false === $this->cookie) {
            if ($this->logger) {
                $this->logger->debug('CookieSessionHandler::onKernelResponse - COOKIE not opened');
            }

            return;
        }

        if (null === $this->cookie) {
            if ($this->logger) {
                $this->logger->debug('CookieSessionHandler::onKernelResponse - CLEAR COOKIE');
            }
            $e->getResponse()->headers->clearCookie($this->cookieName);
        } else {
            $e->getResponse()->headers->setCookie($this->cookie);
        }
    }

    public function onKernelRequest(RequestEvent $e): void
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        if ($this->logger) {
            $this->logger->debug('CookieSessionHandler::onKernelRequest - Receiving the Request object');
        }

        $this->request = $e->getRequest();
    }

    public function close(): bool
    {
        return true;
    }

    public function destroy($sessionId): bool
    {
        $this->cookie = null;

        if ($this->logger) {
            $this->logger->debug(sprintf('CookieSessionHandler::destroy sessionId=%s', $sessionId));
        }

        return true;
    }

    /**
     * {@inheritdoc}
     *
     * @return int|false
     */
    #[\ReturnTypeWillChange]
    public function gc($maxlifetime)
    {
        return 0;
    }

    public function open($savePath, $sessionId): bool
    {
        if (!$this->request) {
            if ($this->logger) {
                $this->logger->critical('CookieSessionHandler::open - The Request object is missing');
            }

            throw new \RuntimeException('You cannot access the session without a Request object set');
        }

        if ($this->logger) {
            $this->logger->debug('CookieSessionHandler::open');
        }

        return true;
    }

    public function read($sessionId): string
    {
        if (!$this->request) {
            if ($this->logger) {
                $this->logger->critical('CookieSessionHandler::read - The Request object is missing');
            }

            throw new \RuntimeException('You cannot access the session without a Request object set');
        }

        if ($this->logger) {
            $this->logger->debug(sprintf('CookieSessionHandler::read sessionId=%s', $sessionId));
        }

        if (!$this->request->cookies->has($this->cookieName)) {
            return '';
        }

        $content = @unserialize($this->request->cookies->get($this->cookieName));

        if (false === $content) {
            $content = [
                'expire' => strtotime('now'),
                'data' => '',
            ];
        }

        if (0 !== $content['expire'] && $content['expire'] < strtotime('now')) {
            return ''; // session expire
        }

        return $content['data'];
    }

    public function write($sessionId, $sessionData): bool
    {
        if ($this->logger) {
            $this->logger->debug(sprintf('CookieSessionHandler::write sessionId=%s', $sessionId));
        }

        $expire = 0 === $this->lifetime ? 0 : strtotime('now') + $this->lifetime;

        $this->cookie = new Cookie(
            $this->cookieName,
            serialize(['expire' => $expire, 'data' => $sessionData]),
            $expire,
            $this->path,
            $this->domain,
            $this->secure,
            $this->httpOnly,
            false,
            Cookie::SAMESITE_LAX
        );

        return true;
    }
}
