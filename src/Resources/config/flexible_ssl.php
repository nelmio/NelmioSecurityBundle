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

use Nelmio\SecurityBundle\EventListener\FlexibleSslListener;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ReferenceConfigurator;
use Symfony\Component\Security\Http\Event\LogoutEvent;

return static function (ContainerConfigurator $containerConfigurator): void {
    $containerConfigurator->services()

        ->set('nelmio_security.flexible_ssl_listener', FlexibleSslListener::class)
            ->args([
                '%nelmio_security.flexible_ssl.cookie_name%',
                '%nelmio_security.flexible_ssl.unsecured_logout%',
                new ReferenceConfigurator('event_dispatcher'),
            ])
            ->tag('kernel.event_listener', [
                'event' => 'kernel.request',
                'method' => 'onKernelRequest',
                'priority' => 20000,
            ])
            ->tag('kernel.event_listener', [
                'event' => 'security.interactive_login',
                'method' => 'onLogin',
            ])
            ->tag('kernel.event_listener', [
                'event' => LogoutEvent::class,
                'method' => 'onLogout',
            ]);
};
