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

use Nelmio\SecurityBundle\ExternalRedirect\AllowListBasedTargetValidator;
use Nelmio\SecurityBundle\ExternalRedirect\ExternalRedirectResponse;
use Nelmio\SecurityBundle\ExternalRedirect\TargetValidator;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Exception\BadRequestException;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

final class ExternalRedirectListener
{
    private bool $abort;
    private ?string $override;
    private ?string $forwardAs;

    private ?TargetValidator $targetValidator;
    private ?LoggerInterface $logger;
    private ?UrlGeneratorInterface $generator;

    /**
     * @param bool                                     $abort           If true, the offending redirects are turned into 403 responses, can't be combined with $override
     * @param string|null                              $override        Absolute path, complete URL or route name that must be used instead of the offending redirect's url
     * @param string|null                              $forwardAs       Name of the route-/query string parameter the blocked url will be passed to destination location
     * @param string|list<string>|TargetValidator|null $targetValidator array of hosts to be allowed, or regex that matches allowed hosts, or implementation of TargetValidator
     * @param LoggerInterface|null                     $logger          A logger, if it's present, detected offenses are logged at the warning level
     * @param UrlGeneratorInterface|null               $generator       Router or equivalent that can generate a route, only if override is a route name
     */
    public function __construct(
        bool $abort = true,
        ?string $override = null,
        ?string $forwardAs = null,
        $targetValidator = null,
        ?LoggerInterface $logger = null,
        ?UrlGeneratorInterface $generator = null
    ) {
        if (null !== $override && $abort) {
            throw new \LogicException('The ExternalRedirectListener can not abort *and* override redirects at the same time.');
        }
        $this->abort = $abort;
        $this->override = $override;
        $this->forwardAs = $forwardAs;

        if (\is_string($targetValidator) || \is_array($targetValidator)) {
            $targetValidator = new AllowListBasedTargetValidator($targetValidator);
        } elseif (null !== $targetValidator && !$targetValidator instanceof TargetValidator) {
            throw new \LogicException('$targetValidator should be an array of hosts, a regular expression, or an implementation of TargetValidator.');
        }
        $this->targetValidator = $targetValidator;

        $this->logger = $logger;
        $this->generator = $generator;
    }

    public function onKernelResponse(ResponseEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        $response = $e->getResponse();

        if (!$response->isRedirect()) {
            return;
        }

        $target = $response->headers->get('Location');

        if (null === $target) {
            return;
        }

        if (!$this->isExternalRedirect($e->getRequest()->getUri(), $target)) {
            return;
        }

        if ($response instanceof ExternalRedirectResponse) {
            $targetValidator = new AllowListBasedTargetValidator($response->getAllowedHosts());
            if ($targetValidator->isTargetAllowed($target)) {
                return;
            }
        }

        if (null !== $this->targetValidator && $this->targetValidator->isTargetAllowed($target)) {
            return;
        }

        if (null !== $this->logger) {
            $this->logger->warning('External redirect detected from '.$e->getRequest()->getUri().' to '.$response->headers->get('Location'));
        }

        if ($this->abort) {
            throw new HttpException(403, 'Invalid Redirect Given: '.$response->headers->get('Location'));
        }

        if (null !== $this->override) {
            $parameters = [];
            if (null !== $this->forwardAs) {
                $parameters[$this->forwardAs] = $response->headers->get('Location');
            }

            if (false === strpos($this->override, '/')) {
                if (null === $this->generator) {
                    throw new \UnexpectedValueException('The listener needs a router/UrlGeneratorInterface object to override invalid redirects with routes');
                }
                $response->headers->set('Location', $this->generator->generate($this->override, $parameters));
            } else {
                $query = '';
                if (\count($parameters) > 0) {
                    $query = (false === strpos($this->override, '?')) ? '?' : '&';
                    $query .= http_build_query($parameters, '', '&');
                }
                $response->headers->set('Location', $this->override.$query);
            }
        }
    }

    public function isExternalRedirect(string $source, string $target): bool
    {
        if (false !== ($i = strpos($target, '\\')) && $i < strcspn($target, '?#')) {
            throw new BadRequestException('Invalid URI: A URI cannot contain a backslash.');
        }
        if (\strlen($target) !== strcspn($target, "\r\n\t")) {
            throw new BadRequestException('Invalid URI: A URI cannot contain CR/LF/TAB characters.');
        }
        if ('' !== $target && (\ord($target[0]) <= 32 || \ord($target[-1]) <= 32)) {
            throw new BadRequestException('Invalid URI: A URI must not start nor end with ASCII control characters or spaces.');
        }

        // handle protocol-relative URLs that parse_url() doesn't like
        if ('//' === substr($target, 0, 2)) {
            $target = 'proto:'.$target;
        }

        $parsedTarget = parse_url($target);
        if (false === $parsedTarget || !isset($parsedTarget['host'])) {
            return false;
        }

        $parsedSource = parse_url($source);
        if (false === $parsedSource || !isset($parsedSource['host'])) {
            throw new \LogicException('The source url must include a host name.');
        }

        return $parsedSource['host'] !== $parsedTarget['host'];
    }
}
