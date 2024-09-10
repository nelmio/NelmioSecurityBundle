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

namespace Nelmio\SecurityBundle\Twig;

use Twig\Environment;

/**
 * @internal
 */
final class Version
{
    public static function needsNodeTag(): bool
    {
        if (Environment::MAJOR_VERSION < 3) {
            return true;
        }

        return Environment::MAJOR_VERSION === 3 && Environment::MINOR_VERSION < 12;
    }
}
