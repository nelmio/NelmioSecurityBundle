<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\Twig\TokenParser;

use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputer;

class CSPStyleParser extends AbstractCSPParser
{
    public function __construct(ShaComputer $shaComputer)
    {
        parent::__construct($shaComputer, 'cspstyle', 'style-src');
    }

    protected function computeSha($data)
    {
        return $this->shaComputer->computeForStyle($data);
    }
}
