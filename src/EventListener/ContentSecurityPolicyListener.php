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

use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;
use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSetBuilderInterface;
use Nelmio\SecurityBundle\ContentSecurityPolicy\LegacyDirectiveSetBuilder;
use Nelmio\SecurityBundle\ContentSecurityPolicy\NonceGeneratorInterface;
use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestMatcherInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

final class ContentSecurityPolicyListener extends AbstractContentTypeRestrictableListener
{
    private DirectiveSetBuilderInterface $reportDirectiveSetBuilder;
    private DirectiveSetBuilderInterface $enforceDirectiveSetBuilder;
    private bool $compatHeaders;

    /**
     * @var list<string>
     */
    private array $hosts;
    private ?string $_nonce = null;
    private ?string $scriptNonce = null;
    private ?string $styleNonce = null;

    /**
     * @var array<string, list<string>>|null
     */
    private ?array $sha = null;
    private NonceGeneratorInterface $nonceGenerator;
    private ShaComputerInterface $shaComputer;
    private ?RequestMatcherInterface $requestMatcher;

    /**
     * @param DirectiveSetBuilderInterface|DirectiveSet $reportDirectiveSetBuilder
     * @param DirectiveSetBuilderInterface|DirectiveSet $enforceDirectiveSetBuilder
     * @param list<string>                              $hosts
     * @param list<string>                              $contentTypes
     */
    public function __construct(
        $reportDirectiveSetBuilder,
        $enforceDirectiveSetBuilder,
        NonceGeneratorInterface $nonceGenerator,
        ShaComputerInterface $shaComputer,
        bool $compatHeaders = true,
        array $hosts = [],
        array $contentTypes = [],
        ?RequestMatcherInterface $requestMatcher = null
    ) {
        parent::__construct($contentTypes);
        $this->reportDirectiveSetBuilder = $this->ensureDirectiveSetBuilder($reportDirectiveSetBuilder);
        $this->enforceDirectiveSetBuilder = $this->ensureDirectiveSetBuilder($enforceDirectiveSetBuilder);
        $this->compatHeaders = $compatHeaders;
        $this->hosts = $hosts;
        $this->nonceGenerator = $nonceGenerator;
        $this->shaComputer = $shaComputer;
        $this->requestMatcher = $requestMatcher;
    }

    public function onKernelRequest(RequestEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        $this->sha = [];
    }

    public function addSha(string $directive, string $sha): void
    {
        if (null === $this->sha) {
            // We're not in a request context, probably in a worker
            // let's disable it to avoid memory leak
            return;
        }

        $this->sha[$directive][] = $sha;
    }

    public function addScript(string $html): void
    {
        if (null === $this->sha) {
            // We're not in a request context, probably in a worker
            // let's disable it to avoid memory leak
            return;
        }

        $this->sha['script-src'][] = $this->shaComputer->computeForScript($html);
    }

    public function addStyle(string $html): void
    {
        if (null === $this->sha) {
            // We're not in a request context, probably in a worker
            // let's disable it to avoid memory leak
            return;
        }

        $this->sha['style-src'][] = $this->shaComputer->computeForStyle($html);
    }

    /**
     * @deprecated Use `nelmio_security.directive_set_builder.report` instead.
     */
    public function getReport(): DirectiveSet
    {
        return $this->reportDirectiveSetBuilder->buildDirectiveSet();
    }

    /**
     * @deprecated Use `nelmio_security.directive_set_builder.enforce` instead.
     */
    public function getEnforcement(): DirectiveSet
    {
        return $this->enforceDirectiveSetBuilder->buildDirectiveSet();
    }

    public function getNonce(string $usage): string
    {
        $nonce = $this->doGetNonce();

        if ('script' === $usage) {
            $this->scriptNonce = $nonce;
        } elseif ('style' === $usage) {
            $this->styleNonce = $nonce;
        } else {
            throw new \InvalidArgumentException('Invalid usage provided');
        }

        return $nonce;
    }

    public function onKernelResponse(ResponseEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        $request = $e->getRequest();
        $response = $e->getResponse();

        if ($response->isRedirection()) {
            $this->_nonce = null;
            $this->styleNonce = null;
            $this->scriptNonce = null;
            $this->sha = null;

            return;
        }

        if (null !== $this->requestMatcher) {
            $match = $this->requestMatcher->matches($request);
        } else {
            $match = ([] === $this->hosts || \in_array($e->getRequest()->getHost(), $this->hosts, true)) && $this->isContentTypeValid($response);
        }

        if ($match) {
            $signatures = $this->sha;
            if (null !== $this->scriptNonce) {
                $signatures['script-src'][] = 'nonce-'.$this->scriptNonce;
            }
            if (null !== $this->styleNonce) {
                $signatures['style-src'][] = 'nonce-'.$this->styleNonce;
            }

            if (!$response->headers->has('Content-Security-Policy-Report-Only')) {
                $response->headers->add($this->buildHeaders($request, $this->reportDirectiveSetBuilder->buildDirectiveSet(), true, $this->compatHeaders, $signatures));
            }
            if (!$response->headers->has('Content-Security-Policy')) {
                $response->headers->add($this->buildHeaders($request, $this->enforceDirectiveSetBuilder->buildDirectiveSet(), false, $this->compatHeaders, $signatures));
            }
        }

        $this->_nonce = null;
        $this->styleNonce = null;
        $this->scriptNonce = null;
        $this->sha = null;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 512],
            KernelEvents::RESPONSE => 'onKernelResponse',
        ];
    }

    private function doGetNonce(): string
    {
        if (null === $this->_nonce) {
            $this->_nonce = $this->nonceGenerator->generate();
        }

        return $this->_nonce;
    }

    /**
     * @param array<string, list<string>>|null $signatures
     *
     * @return array<string, string>
     */
    private function buildHeaders(
        Request $request,
        DirectiveSet $directiveSet,
        bool $reportOnly,
        bool $compatHeaders,
        ?array $signatures = null
    ): array {
        // $signatures might be null if no KernelEvents::REQUEST has been triggered.
        // for instance if a security.authentication.failure has been dispatched
        $headerValue = $directiveSet->buildHeaderValue($request, $signatures);

        if ('' === $headerValue) {
            return [];
        }

        $hn = static function (string $name) use ($reportOnly): string {
            return $name.($reportOnly ? '-Report-Only' : '');
        };

        $headers = [
            $hn('Content-Security-Policy') => $headerValue,
        ];

        if ($compatHeaders) {
            $headers[$hn('X-Content-Security-Policy')] = $headerValue;
        }

        return $headers;
    }

    /**
     * @param DirectiveSetBuilderInterface|DirectiveSet $builderOrDirectiveSet
     */
    private function ensureDirectiveSetBuilder($builderOrDirectiveSet): DirectiveSetBuilderInterface
    {
        if ($builderOrDirectiveSet instanceof DirectiveSetBuilderInterface) {
            return $builderOrDirectiveSet;
        }

        if ($builderOrDirectiveSet instanceof DirectiveSet) {
            trigger_deprecation(
                'nelmio/security-bundle',
                '3.5',
                \sprintf(
                    'Passing %s directly to the %s constructor is deprecated and will be removed in 4.0. Pass a %s instead.',
                    DirectiveSet::class,
                    self::class,
                    DirectiveSetBuilderInterface::class
                )
            );

            return new LegacyDirectiveSetBuilder($builderOrDirectiveSet);
        }

        throw new \InvalidArgumentException(\sprintf('The %s constructor %s expects a or %s.', self::class, DirectiveSetBuilderInterface::class, DirectiveSet::class));
    }
}
