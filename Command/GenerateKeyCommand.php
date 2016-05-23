<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\Command;

use Defuse\Crypto\Key;
use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class GenerateKeyCommand extends ContainerAwareCommand
{
    protected function configure()
    {
        $this
            ->setName('generateKey')
            ->setDescription('Generates a secure encryption key')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        /**
         * @var Key $key
         */
        $key = Key::createNewRandomKey();
        echo "Encryption Key: " . $key->saveToAsciiSafeString() . PHP_EOL;
    }
}
