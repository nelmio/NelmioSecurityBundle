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

use Nelmio\SecurityBundle\EventListener\ReferrerPolicyListener;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return static function (ContainerConfigurator $containerConfigurator): void {
    $containerConfigurator->services()

        ->set('nelmio_security.referrer_policy_listener', ReferrerPolicyListener::class)
            ->args([
                '%nelmio_security.referrer_policy.policies%',
            ])
            ->tag('kernel.event_listener', [
                'event' => 'kernel.response',
                'method' => 'onKernelResponse',
            ]);
};
