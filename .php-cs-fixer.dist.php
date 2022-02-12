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
    '@Symfony:risky' => true,
    'declare_strict_types' => true,
    'header_comment' => ['header' => $header],
    'ordered_class_elements' => true,
    'php_unit_strict' => true,
    'static_lambda' => true,
    'strict_param' => true,
    'ternary_to_null_coalescing' => true,
])
    ->setUsingCache(true)
    ->setRiskyAllowed(true)
    ->setFinder($finder)
    ;
