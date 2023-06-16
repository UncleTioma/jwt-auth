<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) 2014-2021 Sean Tymon <tymon148@gmail.com>
 * (c) 2021 PHP Open Source Saver
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace UncleTioma\JWTAuth\Test\Middleware;

use Illuminate\Http\Request;
use Mockery;
use Mockery\MockInterface;
use UncleTioma\JWTAuth\JWTAuth;
use UncleTioma\JWTAuth\Test\AbstractTestCase;

abstract class AbstractMiddlewareTest extends AbstractTestCase
{
    /**
     * @var MockInterface|JWTAuth
     */
    protected $auth;

    /**
     * @var MockInterface|Request
     */
    protected $request;

    public function setUp(): void
    {
        parent::setUp();

        $this->auth = Mockery::mock(JWTAuth::class);
        $this->request = Mockery::mock(Request::class);
    }
}
