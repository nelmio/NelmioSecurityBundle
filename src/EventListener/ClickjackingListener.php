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

use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

final class ClickjackingListener extends AbstractContentTypeRestrictableListener
{
    /**
     * @var array<string, array<string, string>>
     */
    private array $paths;

    private ?string $hosts;

    /**
     * @param array<string, array<string, string>> $paths
     * @param list<string>                         $contentTypes
     * @param list<string>                         $hosts
     */
    public function __construct(array $paths, array $contentTypes = [], array $hosts = [])
    {
        parent::__construct($contentTypes);
        $this->paths = $paths;
        $this->hosts = [] !== $hosts ? '('.implode('|', $hosts).')' : null;
    }

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::RESPONSE => 'onKernelResponse'];
    }

    public function onKernelResponse(ResponseEvent $e): void
    {
        if (!$e->isMainRequest()) {
            return;
        }

        if (!$this->isContentTypeValid($e->getResponse())) {
            return;
        }

        $response = $e->getResponse();

        if ($response->isRedirection()) {
            return;
        }

        if ($response->headers->has('X-Frame-Options')) {
            // Do not overwrite an existing header
            return;
        }

        $request = $e->getRequest();

        $host = '' === $request->getHost() ? '/' : $request->getHost();

        // skip non-listed hosts
        if (null !== $this->hosts && 1 !== preg_match('{'.$this->hosts.'}i', $host)) {
            return;
        }

        $currentPath = '' === $request->getRequestUri() ? '/' : $request->getRequestUri();

        foreach ($this->paths as $path => $options) {
            if (1 === preg_match('{'.$path.'}i', $currentPath)) {
                if ('ALLOW' === $options['header']) {
                    $response->headers->remove('X-Frame-Options');
                } else {
                    $response->headers->set('X-Frame-Options', $options['header']);
                }

                return;
            }
        }
    }
}
