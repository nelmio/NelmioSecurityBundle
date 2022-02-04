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

use Nelmio\SecurityBundle\Session\CookieSessionHandler;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ReferenceConfigurator;

return static function (ContainerConfigurator $containerConfigurator): void {
    $containerConfigurator->services()

        ->set('nelmio_security.session.handler', CookieSessionHandler::class)
            ->args([
                '%nelmio_security.cookie_session.name%',
                '%nelmio_security.cookie_session.lifetime%',
                '%nelmio_security.cookie_session.path%',
                '%nelmio_security.cookie_session.domain%',
                '%nelmio_security.cookie_session.secure%',
                '%nelmio_security.cookie_session.httponly%',
                new ReferenceConfigurator('logger'),
            ])
            ->tag('kernel.event_listener', [
                'event' => 'kernel.request',
                'method' => 'onKernelRequest',
                'priority' => 9998,
            ])
            ->tag('kernel.event_listener', [
                'event' => 'kernel.response',
                'method' => 'onKernelResponse',
                'priority' => -9998,
            ]);
};
