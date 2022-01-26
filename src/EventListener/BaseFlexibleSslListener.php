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

use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Security\Http\Logout\LogoutHandlerInterface;

if (version_compare(Kernel::VERSION, '5.1', '<')) {
    /**
     * @internal
     */
    interface BaseFlexibleSslListener extends LogoutHandlerInterface
    {
    }
} else {
    /**
     * @internal
     */
    interface BaseFlexibleSslListener
    {
    }
}
