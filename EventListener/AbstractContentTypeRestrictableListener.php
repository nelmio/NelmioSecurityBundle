<?php

namespace Nelmio\SecurityBundle\EventListener;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

abstract class AbstractContentTypeRestrictableListener implements EventSubscriberInterface
{
    protected $contentTypes;

    protected function isContentTypeValid(Response $response)
    {
        if (empty($this->contentTypes)) {
            return true;
        }

        $contentTypeData = explode(';', $response->headers->get('content-type'), 2);

        return in_array(trim($contentTypeData[0]), $this->contentTypes, true);
    }
}
