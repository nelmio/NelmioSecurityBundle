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

use Nelmio\SecurityBundle\PermissionsPolicy\Mapping;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

/**
 * @author Silas Joisten <silasjoisten@proton.me>
 */
final class PermissionsPolicyListener
{
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

        $response = $e->getResponse();

        $policies = [];
        /* @var array|string|null $values */
        foreach ($this->policies as $name => $values) {
            $name = str_replace('_', '-', $name);

            if (null === $values) {
                continue;
            }

            if ('default' === $values) {
                $values = Mapping::get($name);
            } else {
                $values = array_map(static fn (string $value): string => \in_array($value, Mapping::ALLOWED_VALUES, true) ? $value : \sprintf('"%s"', $value), $values);
            }

            $policies[] = \sprintf('%s=(%s)', $name, implode(' ', $values));
        }

        $response->headers->set('Permissions-Policy', implode(', ', $policies));
    }
}
