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

namespace Nelmio\SecurityBundle\Twig\Node;

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Twig\Compiler;
use Twig\Node\Node;

final class CSPNode extends Node
{
    private ?string $sha;
    private string $directive;

    public function __construct(Node $body, int $lineno, string $tag, string $directive, ?string $sha = null)
    {
        parent::__construct(['body' => $body], [], $lineno, $tag);
        $this->sha = $sha;
        $this->directive = $directive;
    }

    public function compile(Compiler $compiler): void
    {
        $body = $this->getNode('body');

        if (null !== $this->sha) {
            $output = "\$this->env->getRuntime('Nelmio\SecurityBundle\Twig\CSPRuntime')->getListener()->addSha('{$this->directive}', '{$this->sha}');\necho ob_get_clean();\n";
        } elseif ('script-src' === $this->directive) {
            $output = "\$script = ob_get_clean();\n\$this->env->getRuntime('Nelmio\SecurityBundle\Twig\CSPRuntime')->getListener()->addScript(\$script);\necho \$script;\n";
        } elseif ('style-src' === $this->directive) {
            $output = "\$style = ob_get_clean();\n\$this->env->getRuntime('Nelmio\SecurityBundle\Twig\CSPRuntime')->getListener()->addStyle(\$style);\necho \$style;\n";
        } else {
            throw new \InvalidArgumentException(sprintf('Unable to compile for directive "%s"', $this->directive));
        }

        $compiler
            ->addDebugInfo($this)
            ->write("ob_start();\n")
            ->subcompile($body)
            ->write($output)
        ;
    }
}
