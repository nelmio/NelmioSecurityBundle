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

namespace Nelmio\SecurityBundle\ContentSecurityPolicy;

final class ShaComputer implements ShaComputerInterface
{
    private string $type;
    private ?string $favorite = null;

    public function __construct(string $type)
    {
        if (!\in_array($type, ['sha256', 'sha384', 'sha512'], true)) {
            throw new \InvalidArgumentException(\sprintf('Type "%s" is not supported', $type));
        }

        $this->type = $type;
    }

    public function computeForScript(string $html): string
    {
        if (1 !== preg_match_all('/<script[^>]*+>/i', $html, $m)) {
            throw new \InvalidArgumentException('Invalid script, you should use a single <script> tag.');
        }

        preg_match('/^\s*+<script[^>]*+>((?s).*)<\/script>\s*+$/i', $html, $matches);

        if (!isset($matches[1])) {
            throw new \InvalidArgumentException('Invalid script, no <script> tag found.');
        }

        return $this->compute($matches[1]);
    }

    public function computeForStyle(string $html): string
    {
        if (1 !== preg_match_all('/<style[^>]*+>/i', $html, $m)) {
            throw new \InvalidArgumentException('Invalid script, you should use a single <style> tag.');
        }

        preg_match('/^\s*+<style[^>]*+>((?s).*)<\/style>\s*+$/i', $html, $matches);

        if (!isset($matches[1])) {
            throw new \InvalidArgumentException('Invalid script, no <style> tag found.');
        }

        return $this->compute($matches[1]);
    }

    private function getFavorite(): string
    {
        if (null !== $this->favorite) {
            return $this->favorite;
        }

        if (\function_exists('hash_algos') && \in_array($this->type, hash_algos(), true)) {
            return $this->favorite = 'hash';
        }

        if (\function_exists('openssl_get_md_methods') && \in_array($this->type, openssl_get_md_methods(), true)) {
            return $this->favorite = 'openssl';
        }

        throw new \RuntimeException('No hash function on this platform');
    }

    private function compute(string $data): string
    {
        return \sprintf('%s-%s', $this->type, base64_encode($this->computeHash($data)));
    }

    private function computeHash(string $data): string
    {
        switch ($this->getFavorite()) {
            case 'openssl':
                $hash = openssl_digest($data, $this->type, true);

                if (false === $hash) {
                    throw new \RuntimeException('Failed executing "openssl_digest".');
                }

                return $hash;
            case 'hash':
                return hash($this->type, $data, true);
        }

        throw new \RuntimeException('No hash function on this platform');
    }
}
