<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\Tests\Listener;

use Nelmio\SecurityBundle\EventListener\ClickjackingListener;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;

class ClickjackingListenerTest extends \PHPUnit_Framework_TestCase
{
    private $kernel;
    private $listener;

    protected function setUp()
    {
        $this->kernel = $this->getMock('Symfony\Component\HttpKernel\HttpKernelInterface');
        $this->listener = new ClickjackingListener(array(
            '^/frames/' => array('header' => 'ALLOW'),
            '/frames/' => array('header' => 'SAMEORIGIN'),
            '^/.*' => array('header' => 'DENY'),
            '.*' => array('header' => 'ALLOW'),
        ));
    }

    /**
     * @dataProvider provideClickjackingMatches
     */
    public function testClickjackingMatches($path, $result)
    {
        $response = $this->callListener($this->listener, $path, true);
        $this->assertEquals($result, $response->headers->get('X-Frame-Options'));
    }

    public function provideClickjackingMatches()
    {
        return array(
            array('', 'DENY'),
            array('/', 'DENY'),
            array('/test', 'DENY'),
            array('/frames/foo', null),
            array('/sub/frames/foo', 'SAMEORIGIN'),
        );
    }

    public function testClickjackingSkipsSubReqs()
    {
        $response = $this->callListener($this->listener, '/', false);
        $this->assertEquals(null, $response->headers->get('X-Frame-Options'));
    }

    protected function callListener($listener, $path, $masterReq, $contentType = 'text/html')
    {
        $request = Request::create($path);
        $response = new Response();
        $response->headers->add(array('content-type' => $contentType));

        $event = new FilterResponseEvent($this->kernel, $request, $masterReq ? HttpKernelInterface::MASTER_REQUEST : HttpKernelInterface::SUB_REQUEST, $response);
        $listener->onKernelResponse($event);

        return $response;
    }

    /**
     * @dataProvider provideContentTypeForrestrictions
     */
    public function testClickjackingWithContentTypes($contentType, $result)
    {
        $this->listener = new ClickjackingListener(array(
            '^/frames/' => array('header' => 'ALLOW'),
            '/frames/' => array('header' => 'SAMEORIGIN'),
            '^/.*' => array('header' => 'DENY'),
            '.*' => array('header' => 'ALLOW'),
        ), array('text/html'));

        $response = $this->callListener($this->listener, '/', true, $contentType);
        $this->assertEquals($result, $response->headers->get('X-Frame-Options'));
    }

    public function provideContentTypeForrestrictions()
    {
        return array(
            array('application/json', null),
            array('text/html', 'DENY'),
        );
    }
}
