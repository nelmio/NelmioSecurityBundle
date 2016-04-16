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

interface TargetValidator
{
    /**
     * Returns whether a target is acceptable.
     *
     * @param string $targetUrl
     * @return boolean
     */
    public function isTargetAllowed($targetUrl);
}
