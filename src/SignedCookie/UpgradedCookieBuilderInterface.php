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

interface UpgradedCookieBuilderInterface
{
    public function build(string $name, ?string $value): ?Cookie;
}
