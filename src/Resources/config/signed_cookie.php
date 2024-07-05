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
use Nelmio\SecurityBundle\Signer;
use Nelmio\SecurityBundle\Signer\SignerInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ReferenceConfigurator;

return static function (ContainerConfigurator $containerConfigurator): void {
    $containerConfigurator->services()

        ->set('nelmio_security.signed_cookie_listener', SignedCookieListener::class)
            ->args([
                new ReferenceConfigurator('nelmio_security.signer'),
                '%nelmio_security.signed_cookie.names%',
            ])
            ->tag('kernel.event_listener', [
                'event' => 'kernel.request',
                'method' => 'onKernelRequest',
                'priority' => 10000,
            ])
            ->tag('kernel.event_listener', [
                'event' => 'kernel.response',
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
    ;
};
