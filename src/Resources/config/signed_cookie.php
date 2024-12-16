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

use Nelmio\SecurityBundle\EventListener\SignedCookieListener;
use Nelmio\SecurityBundle\EventListener\SignedCookieUpgradeListener;
use Nelmio\SecurityBundle\SignedCookie\LegacySignatureCookieTracker;
use Nelmio\SecurityBundle\SignedCookie\LegacySignatureCookieTrackerInterface;
use Nelmio\SecurityBundle\SignedCookie\UpgradedCookieBuilderInterface;
use Nelmio\SecurityBundle\SignedCookie\UpgradedCookieBuilderRegistry;
use Nelmio\SecurityBundle\Signer;
use Nelmio\SecurityBundle\Signer\SignerInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ReferenceConfigurator;
use Symfony\Component\HttpKernel\KernelEvents;

use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

return static function (ContainerConfigurator $containerConfigurator): void {
    $containerConfigurator->services()

        ->set('nelmio_security.signed_cookie_listener', SignedCookieListener::class)
            ->args([
                new ReferenceConfigurator('nelmio_security.signer'),
                '%nelmio_security.signed_cookie.names%',
                new ReferenceConfigurator('nelmio_security.legacy_signature_cookie_tracker'),
            ])
            ->tag('kernel.event_listener', [
                'event' => KernelEvents::REQUEST,
                'method' => 'onKernelRequest',
                'priority' => 10000,
            ])
            ->tag('kernel.event_listener', [
                'event' => KernelEvents::RESPONSE,
                'method' => 'onKernelResponse',
                'priority' => -10000,
            ])

        ->set('nelmio_security.signer', Signer::class)
            ->args([
                '%nelmio_security.signer.secret%',
                '%nelmio_security.signer.hash_algo%',
                '%nelmio_security.signer.legacy_hash_algo%',
                '%nelmio_security.signer.separator%',
            ])

        ->alias(SignerInterface::class, 'nelmio_security.signer')

        ->set('nelmio_security.signed_cookie_upgrade_listener', SignedCookieUpgradeListener::class)
            ->args([
                new ReferenceConfigurator('nelmio_security.legacy_signature_cookie_tracker'),
                new ReferenceConfigurator('nelmio_security.upgraded_cookie_builder_registry'),
            ])
            ->tag('kernel.event_listener', [
                'event' => KernelEvents::RESPONSE,
                'method' => 'onKernelResponse',
                'priority' => -9990,
            ])

        ->set('nelmio_security.legacy_signature_cookie_tracker', LegacySignatureCookieTracker::class)

        ->alias(LegacySignatureCookieTrackerInterface::class, 'nelmio_security.legacy_signature_cookie_tracker')

        ->set('nelmio_security.upgraded_cookie_builder_registry', UpgradedCookieBuilderRegistry::class)
            ->args([
                tagged_iterator('nelmio_security.upgraded_cookie_builder'),
            ])

        ->alias(UpgradedCookieBuilderInterface::class, 'nelmio_security.upgraded_cookie_builder_registry')
    ;
};
