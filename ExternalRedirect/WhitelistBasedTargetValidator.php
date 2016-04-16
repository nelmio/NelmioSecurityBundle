<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\ExternalRedirect;

class WhitelistBasedTargetValidator implements TargetValidator
{
    private $whitelist;

    public function __construct($whitelist = null)
    {
        if (is_array($whitelist)) {
            if ($whitelist) {
                $whitelist = array_map(function ($el) {
                    return preg_quote(ltrim($el, '.'));
                }, $whitelist);
                $whitelist = '(?:.*\.'.implode('|.*\.', $whitelist).'|'.implode('|', $whitelist).')';
            } else {
                $whitelist = null;
            }
        }
        $this->whitelist = $whitelist;
    }

    public function isTargetAllowed($target)
    {
        if ($this->whitelist === null || empty($this->whitelist)) {
            return false;
        }

        return preg_match('{^'.$this->whitelist.'$}i', parse_url($target, PHP_URL_HOST)) > 0;
    }
}
