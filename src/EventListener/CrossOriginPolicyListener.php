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

use Symfony\Component\HttpKernel\Event\ResponseEvent;

/**
 * @author Florent Morselli <florent.morselli@spomky-labs.com>
 *
 * @internal
 */
final class CrossOriginPolicyListener
{
    /**
     * @var array<string, array{coep?: string, coop?: string, corp?: string, report_only?: bool, report_to?: string|null}>
     */
    private array $paths;

    /**
     * @param array<string, array{coep?: string, coop?: string, corp?: string, report_only?: bool, report_to?: string|null}> $paths
     */
    public function __construct(array $paths)
    {
        $this->paths = $paths;
    }

    public function onKernelResponse(ResponseEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        $response = $e->getResponse();

        if ($response->isRedirection()) {
            return;
        }

        $request = $e->getRequest();

        $currentPath = '' === $request->getRequestUri() ? '/' : $request->getRequestUri();

        foreach ($this->paths as $path => $options) {
            if (1 === preg_match('{'.$path.'}i', $currentPath)) {
                $reportOnly = $options['report_only'] ?? false;
                $reportTo = $options['report_to'] ?? null;

                // Handle COEP
                if (isset($options['coep'])) {
                    $coepValue = $options['coep'];
                    if (null !== $reportTo) {
                        $coepValue .= '; report-to="'.$reportTo.'"';
                    }
                    $coepHeader = $reportOnly ? 'Cross-Origin-Embedder-Policy-Report-Only' : 'Cross-Origin-Embedder-Policy';
                    $response->headers->set($coepHeader, $coepValue);
                }

                // Handle COOP
                if (isset($options['coop'])) {
                    $coopValue = $options['coop'];
                    if (null !== $reportTo) {
                        $coopValue .= '; report-to="'.$reportTo.'"';
                    }
                    $coopHeader = $reportOnly ? 'Cross-Origin-Opener-Policy-Report-Only' : 'Cross-Origin-Opener-Policy';
                    $response->headers->set($coopHeader, $coopValue);
                }

                // Handle CORP (no report-only or report-to)
                if (isset($options['corp'])) {
                    $response->headers->set('Cross-Origin-Resource-Policy', $options['corp']);
                }

                return;
            }
        }
    }
}
