<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\EventListener;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

abstract class AbstractContentTypeRestrictableListener implements EventSubscriberInterface
{
    protected $contentTypes;

    public function __construct(array $contentTypes)
    {
        $this->contentTypes = $contentTypes;
    }

    protected function isContentTypeValid(Response $response)
    {
        if (empty($this->contentTypes)) {
            return true;
        }

        $contentTypeData = explode(';', $response->headers->get('content-type'), 2);

        return in_array(trim($contentTypeData[0]), $this->contentTypes, true);
    }
}
