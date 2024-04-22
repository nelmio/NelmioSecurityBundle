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

use Twig\Attribute\YieldReady;
use Twig\Compiler;
use Twig\Node\CaptureNode;
use Twig\Node\Node;

#[YieldReady]
final class CSPNode extends Node
{
    private ?string $sha;
    private string $directive;

    public function __construct(Node $body, int $lineno, string $tag, string $directive, ?string $sha = null)
    {
        if (class_exists(CaptureNode::class)) {
            $body = new CaptureNode($body, $lineno, $tag);
            $body->setAttribute('raw', true);
        }

        parent::__construct(['body' => $body], [], $lineno, $tag);
        $this->sha = $sha;
        $this->directive = $directive;
    }

    public function compile(Compiler $compiler): void
    {
        if (class_exists(CaptureNode::class)) {
            $compiler
                ->addDebugInfo($this)
                ->indent()
                ->write("\$content = ")
                ->subcompile($this->getNode('body'))
                ->raw("\n")
                ->outdent()
            ;
        } else {
            $compiler
                ->addDebugInfo($this)
                ->indent()
                ->write("ob_start();\n")
                ->subcompile($this->getNode('body'))
                ->outdent()
                ->write("\$content = ob_get_clean();\n")
            ;
        }

        if (null !== $this->sha) {
            $compiler->write("\$this->env->getRuntime('Nelmio\SecurityBundle\Twig\CSPRuntime')->getListener()->addSha('{$this->directive}', '{$this->sha}');\n");
        } elseif ('script-src' === $this->directive) {
            $compiler->write("\$this->env->getRuntime('Nelmio\SecurityBundle\Twig\CSPRuntime')->getListener()->addScript(\$content);\n");
        } elseif ('style-src' === $this->directive) {
            $compiler->write("\$this->env->getRuntime('Nelmio\SecurityBundle\Twig\CSPRuntime')->getListener()->addStyle(\$content);\n");
        } else {
            throw new \InvalidArgumentException(sprintf('Unable to compile for directive "%s"', $this->directive));
        }
        $compiler->write("echo \$content;\n");
    }
}
