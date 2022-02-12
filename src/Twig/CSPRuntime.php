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

use Nelmio\SecurityBundle\EventListener\ContentSecurityPolicyListener;
use Twig\Extension\RuntimeExtensionInterface;

/**
 * @internal
 */
final class CSPRuntime implements RuntimeExtensionInterface
{
    private ContentSecurityPolicyListener $listener;

    public function __construct(ContentSecurityPolicyListener $listener)
    {
        $this->listener = $listener;
    }

    public function getListener(): ContentSecurityPolicyListener
    {
        return $this->listener;
    }

    public function getCSPNonce(string $usage): string
    {
        return $this->listener->getNonce($usage);
    }
}
