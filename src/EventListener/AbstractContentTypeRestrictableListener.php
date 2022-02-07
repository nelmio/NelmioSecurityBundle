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

namespace Nelmio\SecurityBundle\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Response;

abstract class AbstractContentTypeRestrictableListener implements EventSubscriberInterface
{
    /**
     * @var list<string>
     */
    private array $contentTypes;

    /**
     * @param list<string> $contentTypes
     */
    public function __construct(array $contentTypes)
    {
        $this->contentTypes = $contentTypes;
    }

    protected function isContentTypeValid(Response $response): bool
    {
        if ([] === $this->contentTypes) {
            return true;
        }

        if (null === $response->headers->get('content-type')) {
            return false;
        }

        $contentTypeData = explode(';', $response->headers->get('content-type'), 2);

        return \in_array(trim($contentTypeData[0]), $this->contentTypes, true);
    }
}
