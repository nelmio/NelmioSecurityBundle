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

$header = <<<'EOF'
This file is part of the Nelmio SecurityBundle.

(c) Nelmio <hello@nelm.io>

For the full copyright and license information, please view the LICENSE
file that was distributed with this source code.
EOF;

$finder = PhpCsFixer\Finder::create()
    ->in(__DIR__.'/src')
    ->in(__DIR__.'/tests')
    ->append([__FILE__])
;

$config = new PhpCsFixer\Config();

return $config->setRules([
    '@PSR2' => true,
    '@Symfony' => true,
    'header_comment' => ['header' => $header],
])
    ->setUsingCache(true)
    ->setRiskyAllowed(true)
    ->setFinder($finder)
    ;
