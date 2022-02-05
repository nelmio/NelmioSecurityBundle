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
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

final class XssProtectionListener implements EventSubscriberInterface
{
    use KernelEventForwardCompatibilityTrait;

    private bool $enabled;
    private bool $modeBlock;
    private ?string $reportUri;

    public function __construct(bool $enabled, bool $modeBlock, ?string $reportUri = null)
    {
        $this->enabled = $enabled;
        $this->modeBlock = $modeBlock;
        $this->reportUri = $reportUri;
    }

    public function onKernelResponse(ResponseEvent $e): void
    {
        if (!$this->isMainRequest($e)) {
            return;
        }

        $response = $e->getResponse();

        if ($response->isRedirection()) {
            return;
        }

        $value = '0';
        if ($this->enabled) {
            $value = '1';

            if ($this->modeBlock) {
                $value .= '; mode=block';
            }

            if (null !== $this->reportUri) {
                $value .= '; report='.$this->reportUri;
            }
        }

        $response->headers->set('X-XSS-Protection', $value);
    }

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::RESPONSE => 'onKernelResponse'];
    }

    /**
     * @phpstan-param array{enabled: bool, mode_block: bool, report_uri: string|null} $config
     */
    public static function fromConfig(array $config): self
    {
        $enabled = $config['enabled'];
        $modeBlock = $config['mode_block'];
        $reportUri = $config['report_uri'];

        return new self($enabled, $modeBlock, $reportUri);
    }
}
