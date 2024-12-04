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

namespace Nelmio\SecurityBundle\SignedCookie;

use Symfony\Component\HttpFoundation\Cookie;

class UpgradedCookieBuilderRegistry implements UpgradedCookieBuilderInterface
{
    /**
     * @var iterable<UpgradedCookieBuilderInterface>
     */
    private iterable $builders;

    /**
     * @param iterable<UpgradedCookieBuilderInterface> $builders
     */
    public function __construct(iterable $builders)
    {
        $this->builders = $builders;
    }

    public function build(string $name, ?string $value): ?Cookie
    {
        foreach ($this->builders as $builder) {
            $cookie = $builder->build($name, $value);
            if (null !== $cookie) {
                return $cookie;
            }
        }

        return null;
    }
}
