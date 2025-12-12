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
     * @var array<string, array{coep?: array{value: string, report_only: bool, report_to: string|null}, coop?: array{value: string, report_only: bool, report_to: string|null}, corp?: string}>
     */
    private array $paths;

    /**
     * @param array<string, array{coep?: array{value: string, report_only: bool, report_to: string|null}, coop?: array{value: string, report_only: bool, report_to: string|null}, corp?: string}> $paths
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
                // Handle COEP
                if (isset($options['coep'])) {
                    $coep = $options['coep'];
                    $coepValue = $coep['value'];
                    if (null !== $coep['report_to']) {
                        $coepValue .= '; report-to="'.$coep['report_to'].'"';
                    }
                    $coepHeader = $coep['report_only'] ? 'Cross-Origin-Embedder-Policy-Report-Only' : 'Cross-Origin-Embedder-Policy';
                    $response->headers->set($coepHeader, $coepValue);
                }

                // Handle COOP
                if (isset($options['coop'])) {
                    $coop = $options['coop'];
                    $coopValue = $coop['value'];
                    if (null !== $coop['report_to']) {
                        $coopValue .= '; report-to="'.$coop['report_to'].'"';
                    }
                    $coopHeader = $coop['report_only'] ? 'Cross-Origin-Opener-Policy-Report-Only' : 'Cross-Origin-Opener-Policy';
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
