<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\Session;

use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpKernel\Log\LoggerInterface;

class CookieSessionHandler implements \SessionHandlerInterface
{
    protected $request;

    protected $response;

    protected $cookieName;

    protected $lifetime;

    protected $path;

    protected $domain;

    protected $secure;

    protected $httpOnly;

    protected $cookie = false;

    /**
     * @param string          $cookieName
     * @param int             $lifetime
     * @param string          $path
     * @param string          $domain
     * @param bool            $secure
     * @param bool            $httpOnly
     * @param LoggerInterface $logger
     */
    public function __construct($cookieName, $lifetime = 0, $path = '/', $domain = null, $secure = false, $httpOnly = true, LoggerInterface $logger = null)
    {
        $this->cookieName = $cookieName;
        $this->path = $path;
        $this->domain = $domain;
        $this->lifetime = (int) $lifetime;
        $this->secure = $secure;
        $this->httpOnly = $httpOnly;
        $this->logger = $logger;
    }

    /**
     * @param FilterResponseEvent $e
     */
    public function onKernelResponse(FilterResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        if ($this->logger) {
            $this->logger->debug('CookieSessionHandler::onKernelResponse - Get the Response object');
        }

        $this->request->getSession()->save();

        if ($this->cookie === false) {
            if ($this->logger) {
                $this->logger->debug('CookieSessionHandler::onKernelResponse - COOKIE not opened');
            }

            return;
        }

        if ($this->cookie === null) {
            if ($this->logger) {
                $this->logger->debug('CookieSessionHandler::onKernelResponse - CLEAR COOKIE');
            }
            $e->getResponse()->headers->clearCookie($this->cookieName);
        } else {
            $e->getResponse()->headers->setCookie($this->cookie);
        }
    }

    /**
     * @param GetResponseEvent $e
     */
    public function onKernelRequest(GetResponseEvent $e)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $e->getRequestType()) {
            return;
        }

        if ($this->logger) {
            $this->logger->debug('CookieSessionHandler::onKernelRequest - Receiving the Request object');
        }

        $this->request = $e->getRequest();
    }

    /**
     * {@inheritdoc}
     */
    public function close()
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function destroy($sessionId)
    {
        $this->cookie = null;

        if ($this->logger) {
            $this->logger->debug(sprintf('CookieSessionHandler::destroy sessionId=%s', $sessionId));
        }

        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function gc($maxlifetime)
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function open($savePath, $sessionId)
    {
        if (!$this->request) {
            if ($this->logger) {
                $this->logger->crit('CookieSessionHandler::open - The Request object is missing');
            }

            throw new \RuntimeException('You cannot access the session without a Request object set');
        }

        if ($this->logger) {
            $this->logger->debug('CookieSessionHandler::open');
        }

        return $this->request->cookies->has($this->cookieName);
    }

    /**
     * {@inheritdoc}
     */
    public function read($sessionId)
    {
        if (!$this->request) {
            if ($this->logger) {
                $this->logger->crit('CookieSessionHandler::read - The Request object is missing');
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

        if ($content === false) {
            $content = array(
                'expire' => strtotime('now'),
                'data'   => ''
            );
        }

        if ($content['expire'] !== 0 && $content['expire'] < strtotime('now')) {
            return ''; // session expire
        }

        return $content['data'];
    }

    /**
     * {@inheritdoc}
     */
    public function write($sessionId, $sessionData)
    {
        if ($this->logger) {
            $this->logger->debug(sprintf('CookieSessionHandler::write sessionId=%s', $sessionId));
        }

        $expire = $this->lifetime === 0 ? 0 : strtotime('now') + $this->lifetime;

        $this->cookie = new Cookie(
            $this->cookieName,
            serialize(array('expire' => $expire, 'data' => $sessionData)),
            $expire,
            $this->path,
            $this->domain,
            $this->secure,
            $this->httpOnly
        );

        return true;
    }
}
