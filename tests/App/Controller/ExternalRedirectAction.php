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

namespace Nelmio\SecurityBundle\Tests\App\Controller;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

final class ExternalRedirectAction
{
    public function __invoke(): Response
    {
        return new RedirectResponse('https://symfony.com');
    }
}
