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

use Nelmio\SecurityBundle\EventListener\ForcedSslListener;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return static function (ContainerConfigurator $containerConfigurator): void {
    $containerConfigurator->services()

        ->set('nelmio_security.forced_ssl_listener', ForcedSslListener::class)
            ->args([
                '%nelmio_security.forced_ssl.hsts_max_age%',
                '%nelmio_security.forced_ssl.hsts_subdomains%',
                '%nelmio_security.forced_ssl.hsts_preload%',
                '%nelmio_security.forced_ssl.allow_list%',
                '%nelmio_security.forced_ssl.hosts%',
                '%nelmio_security.forced_ssl.redirect_status_code%',
            ])
            ->tag('kernel.event_listener', [
                'event' => 'kernel.request',
                'method' => 'onKernelRequest',
                'priority' => 30000,
            ]);
};
