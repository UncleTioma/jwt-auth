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

namespace UncleTioma\JWTAuth\Test\Claims;

use UncleTioma\JWTAuth\Claims\NotBefore;
use UncleTioma\JWTAuth\Exceptions\InvalidClaimException;
use UncleTioma\JWTAuth\Test\AbstractTestCase;

class NotBeforeTest extends AbstractTestCase
{
    /** @test */
    public function itShouldThrowAnExceptionWhenPassingAnInvalidValue()
    {
        $this->expectException(InvalidClaimException::class);
        $this->expectExceptionMessage('Invalid value provided for claim [nbf]');

        new NotBefore('foo');
    }
}
