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

namespace Nelmio\SecurityBundle\Twig\TokenParser;

use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputerInterface;

final class CSPScriptParser extends AbstractCSPParser
{
    public function __construct(ShaComputerInterface $shaComputer)
    {
        parent::__construct($shaComputer, 'cspscript', 'script-src');
    }

    protected function computeSha(string $data): string
    {
        return $this->shaComputer->computeForScript($data);
    }
}
