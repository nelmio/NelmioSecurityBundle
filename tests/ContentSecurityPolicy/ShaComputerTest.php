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

namespace Nelmio\SecurityBundle\Tests\ContentSecurityPolicy;

use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputer;
use PHPUnit\Framework\TestCase;

class ShaComputerTest extends TestCase
{
    /**
     * @dataProvider provideValidScriptCode
     */
    public function testComputeScript(string $expected, string $code): void
    {
        $shaComputer = new ShaComputer('sha256');
        $this->assertSame($expected, $shaComputer->computeForScript($code));
    }

    public function provideValidScriptCode(): array
    {
        $mdMultiline = 'sha256-FJZognZIK0t5xLh8JBt4m/9rjpkYa4lTySrcUdRWHPM=';
        $md = 'sha256-lClGOfcWqtQdAvO3zCRzZEg/4RmOMbr9/V54QO76j/A=';

        return [
            [$mdMultiline, "

            <script>
            console.log('hello world!');
            </script>

            "],
            [$md, "<script>console.log('hello world!');</script>"],
            [$md, "<script crossorigin=\"anonymous\">console.log('hello world!');</script>"],
            [$md, "<SCRIPT>console.log('hello world!');</SCRIPT>"],
            [$md, "<SCRIPT crossorigin=\"anonymous\">console.log('hello world!');</SCRIPT>"],
        ];
    }

    /**
     * @dataProvider provideValidStyleCode
     */
    public function testComputeStyle(string $expected, string $code): void
    {
        $shaComputer = new ShaComputer('sha256');
        $this->assertSame($expected, $shaComputer->computeForStyle($code));
    }

    public function provideValidStyleCode(): array
    {
        $mdMultiline = 'sha256-VbDrDAWYPqj9uExrJNmpK8bKIArMizR2+jcPhqSXO8M=';
        $md = 'sha256-dmskSo+yqoLHXIXCFWnQJvCkjkJJmENqTDRi5+il2Yw=';

        return [
            [$mdMultiline, '

            <style>
                body {
                    background-color: black;
                }
            </style>

            '],
            [$md, '<style>body { background-color: black; }</style>'],
            [$md, '<style type="text/css">body { background-color: black; }</style>'],
            [$md, '<STYLE>body { background-color: black; }</STYLE>'],
            [$md, '<STYLE crossorigin="anonymous">body { background-color: black; }</STYLE>'],
        ];
    }

    /**
     * @dataProvider provideInvalidScriptCode
     */
    public function testComputeScriptShouldFail(string $code): void
    {
        $this->expectException('InvalidArgumentException');

        $shaComputer = new ShaComputer('sha256');
        $shaComputer->computeForScript($code);
    }

    public function provideInvalidScriptCode(): array
    {
        return [
            [' <script> </script> <script> </script> '],
            [' <script>'],
            [''],
            [' <style></style'],
        ];
    }
}
