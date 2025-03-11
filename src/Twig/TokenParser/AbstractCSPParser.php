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

namespace Nelmio\SecurityBundle\Twig\TokenParser;

use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputerInterface;
use Nelmio\SecurityBundle\Twig\Node\CSPNode;
use Twig\Node\TextNode;
use Twig\Token;
use Twig\TokenParser\AbstractTokenParser;

abstract class AbstractCSPParser extends AbstractTokenParser
{
    protected ShaComputerInterface $shaComputer;
    private string $directive;
    private string $tag;

    public function __construct(ShaComputerInterface $shaComputer, string $tag, string $directive)
    {
        $this->shaComputer = $shaComputer;
        $this->tag = $tag;
        $this->directive = $directive;
    }

    public function parse(Token $token): CSPNode
    {
        $lineno = $token->getLine();

        $this->parser->getStream()->expect(Token::BLOCK_END_TYPE);
        $body = $this->parser->subparse([$this, 'decideCSPScriptEnd'], true);
        $this->parser->getStream()->expect(Token::BLOCK_END_TYPE);

        $sha = null;
        if ($body instanceof TextNode) {
            \assert(\is_string($body->getAttribute('data')));
            $sha = $this->computeSha($body->getAttribute('data'));
        }

        return new CSPNode($body, $lineno, $this->tag, $this->directive, $sha);
    }

    public function decideCSPScriptEnd(Token $token): bool
    {
        return $token->test('end'.$this->tag);
    }

    public function getTag(): string
    {
        return $this->tag;
    }

    abstract protected function computeSha(string $data): string;
}
