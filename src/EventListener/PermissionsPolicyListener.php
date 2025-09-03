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
 * @author Silas Joisten <silasjoisten@proton.me>
 */
final class PermissionsPolicyListener
{
    /**
     * @var list<string>
     */
    public const ALLOWED_VALUES = [
        '*',
        'self',
        'src',
    ];

    /**
     * @var array<string, string[]>
     */
    private array $policies;

    /**
     * @param array<string, string[]> $policies
     */
    public function __construct(array $policies)
    {
        $this->policies = $policies;
    }

    public function onKernelResponse(ResponseEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        if ([] === $this->policies) {
            return;
        }

        // Firefox and Safari do not support Permissions-Policy header in general
        $userAgent = \strtolower($e->getRequest()->headers->get('user-agent', ''));
        if (0 !== \preg_match('/\b(firefox|safari)\b/', $userAgent)) {
            return;
        }

        $response = $e->getResponse();

        $policies = [];
        foreach ($this->policies as $name => $values) {
            $values = \array_map(static fn(string $value): string => \in_array($value, self::ALLOWED_VALUES, true) ? $value : \sprintf('"%s"', $value), $values);
            $policies[] = \sprintf('%s=(%s)', \str_replace('_', '-', $name), \implode(' ', $values));
        }

        $response->headers->set('Permissions-Policy', \implode(', ', $policies));
    }
}
