<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\UserAgent\UAFamilyParser;

use UAParser\Parser;

class UAFamilyParser implements UAFamilyParserInterface
{
    private $parser;

    public function __construct(Parser $parser)
    {
        $this->parser = $parser;
    }

    public function getUaFamily($userAgent)
    {
        return strtolower($this->parser->parse((string) $userAgent)->ua->family);
    }
}
