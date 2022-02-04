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

use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputerInterface;
use Nelmio\SecurityBundle\Twig\TokenParser\CSPScriptParser;
use Nelmio\SecurityBundle\Twig\TokenParser\CSPStyleParser;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

final class NelmioCSPTwigExtension extends AbstractExtension
{
    private ShaComputerInterface $shaComputer;

    public function __construct(ShaComputerInterface $shaComputer)
    {
        $this->shaComputer = $shaComputer;
    }

    public function getTokenParsers(): array
    {
        return [new CSPScriptParser($this->shaComputer), new CSPStyleParser($this->shaComputer)];
    }

    public function getFunctions(): array
    {
        return [
            new TwigFunction('csp_nonce', [CSPRuntime::class, 'getCSPNonce']),
        ];
    }
}
