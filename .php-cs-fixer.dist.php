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
    'modernize_strpos' => false, // @todo: Remove this line when dropping support of PHP 7.4
    'no_superfluous_phpdoc_tags' => [
        'allow_mixed' => true,
    ],
    'nullable_type_declaration_for_default_null_value' => true,
    'ordered_class_elements' => true,
    'php_unit_strict' => true,
    'static_lambda' => true,
    'strict_param' => true,
    'ternary_to_null_coalescing' => true,
    'trailing_comma_in_multiline' => ['elements' => ['arrays']],
])
    ->setUsingCache(true)
    ->setRiskyAllowed(true)
    ->setFinder($finder)
;
