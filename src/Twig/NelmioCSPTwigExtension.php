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

use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputer;
use Nelmio\SecurityBundle\EventListener\ContentSecurityPolicyListener;
use Nelmio\SecurityBundle\Twig\TokenParser\CSPScriptParser;
use Nelmio\SecurityBundle\Twig\TokenParser\CSPStyleParser;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

class NelmioCSPTwigExtension extends AbstractExtension
{
    private ContentSecurityPolicyListener $listener;
    private ShaComputer $shaComputer;

    public function __construct(ContentSecurityPolicyListener $listener, ShaComputer $shaComputer)
    {
        $this->listener = $listener;
        $this->shaComputer = $shaComputer;
    }

    public function getTokenParsers(): array
    {
        return [new CSPScriptParser($this->shaComputer), new CSPStyleParser($this->shaComputer)];
    }

    public function getListener(): ContentSecurityPolicyListener
    {
        return $this->listener;
    }

    public function getName(): string
    {
        return NelmioCSPTwigExtension::class;
    }

    public function getFunctions(): array
    {
        return [
            new TwigFunction('csp_nonce', [$this, 'getCSPNonce']),
        ];
    }

    public function getCSPNonce(string $usage): string
    {
        return $this->listener->getNonce($usage);
    }
}
