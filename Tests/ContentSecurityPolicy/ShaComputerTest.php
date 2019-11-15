<?php

namespace Nelmio\SecurityBundle\Tests\ContentSecurityPolicy;

use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputer;

class ShaComputerTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @dataProvider provideValidScriptCode
     */
    public function testComputeScript($expected, $code)
    {
        $shaComputer = new ShaComputer('sha256');
        $this->assertSame($expected, $shaComputer->computeForScript($code));
    }

    public function provideValidScriptCode()
    {
        $mdMultiline = 'sha256-FJZognZIK0t5xLh8JBt4m/9rjpkYa4lTySrcUdRWHPM=';
        $md = 'sha256-lClGOfcWqtQdAvO3zCRzZEg/4RmOMbr9/V54QO76j/A=';

        return array(
            array($mdMultiline, "

            <script>
            console.log('hello world!');
            </script>

            "),
            array($md, "<script>console.log('hello world!');</script>"),
            array($md, "<script crossorigin=\"anonymous\">console.log('hello world!');</script>"),
            array($md, "<SCRIPT>console.log('hello world!');</SCRIPT>"),
            array($md, "<SCRIPT crossorigin=\"anonymous\">console.log('hello world!');</SCRIPT>"),
        );
    }

    /**
     * @dataProvider provideValidStyleCode
     */
    public function testComputeStyle($expected, $code)
    {
        $shaComputer = new ShaComputer('sha256');
        $this->assertSame($expected, $shaComputer->computeForStyle($code));
    }

    public function provideValidStyleCode()
    {
        $mdMultiline = 'sha256-VbDrDAWYPqj9uExrJNmpK8bKIArMizR2+jcPhqSXO8M=';
        $md = 'sha256-dmskSo+yqoLHXIXCFWnQJvCkjkJJmENqTDRi5+il2Yw=';

        return array(
            array($mdMultiline, '

            <style>
                body {
                    background-color: black;
                }
            </style>

            '),
            array($md, '<style>body { background-color: black; }</style>'),
            array($md, '<style type="text/css">body { background-color: black; }</style>'),
            array($md, '<STYLE>body { background-color: black; }</STYLE>'),
            array($md, '<STYLE crossorigin="anonymous">body { background-color: black; }</STYLE>'),
        );
    }

    /**
     * @dataProvider provideInvalidScriptCode
     */
    public function testComputeScriptShouldFail($code)
    {
        $this->expectException(\InvalidArgumentException::class);

        $shaComputer = new ShaComputer('sha256');
        $shaComputer->computeForScript($code);
    }

    public function provideInvalidScriptCode()
    {
        return array(
            array(' <script> </script> <script> </script> '),
            array(' <script>'),
            array(''),
            array(' <style></style'),
        );
    }
}
