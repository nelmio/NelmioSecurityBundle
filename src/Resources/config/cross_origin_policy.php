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

use Nelmio\SecurityBundle\EventListener\CrossOriginPolicyListener;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return static function (ContainerConfigurator $containerConfigurator): void {
    $containerConfigurator->services()

        ->set('nelmio_security.cross_origin_policy_listener', CrossOriginPolicyListener::class)
            ->args([
                '%nelmio_security.cross_origin_policy.coep%',
                '%nelmio_security.cross_origin_policy.coop%',
                '%nelmio_security.cross_origin_policy.corp%',
            ])
            ->tag('kernel.event_listener', [
                'event' => 'kernel.response',
                'method' => 'onKernelResponse',
            ]);
};
