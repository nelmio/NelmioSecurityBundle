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

use Nelmio\SecurityBundle\EventListener\ClickjackingListener;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return static function (ContainerConfigurator $containerConfigurator): void {
    $containerConfigurator->services()

        ->set('nelmio_security.clickjacking_listener', ClickjackingListener::class)
            ->args([
                '%nelmio_security.clickjacking.paths%',
                '%nelmio_security.clickjacking.content_types%',
                '%nelmio_security.clickjacking.hosts%',
            ])
            ->tag('kernel.event_subscriber');
};
