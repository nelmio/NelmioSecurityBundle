<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\Twig\TokenParser;

use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputer;
use Nelmio\SecurityBundle\Twig\Node\CSPNode;
use Twig\Node\TextNode;
use Twig\Token;
use Twig\TokenParser\AbstractTokenParser;

abstract class AbstractCSPParser extends AbstractTokenParser
{
    protected $shaComputer;
    private $directive;
    private $tag;

    public function __construct(ShaComputer $shaComputer, $tag, $directive)
    {
        $this->shaComputer = $shaComputer;
        $this->tag = $tag;
        $this->directive = $directive;
    }

    /**
     * @return CSPNode
     */
    public function parse(Token $token)
    {
        $lineno = $token->getLine();

        $this->parser->getStream()->expect(Token::BLOCK_END_TYPE);
        $body = $this->parser->subparse(array($this, 'decideCSPScriptEnd'), true);
        $this->parser->getStream()->expect(Token::BLOCK_END_TYPE);

        $sha = null;
        if ($body instanceof TextNode) {
            $sha = $this->computeSha($body->getAttribute('data'));
        }

        return new CSPNode($body, $lineno, $this->tag, $this->directive, $sha);
    }

    public function decideCSPScriptEnd(Token $token)
    {
        return $token->test('end'.$this->tag);
    }

    /**
     * @return string
     */
    public function getTag()
    {
        return $this->tag;
    }

    abstract protected function computeSha($data);
}
