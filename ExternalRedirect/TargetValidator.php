<?php

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
