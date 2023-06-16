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

use UncleTioma\JWTAuth\Claims\Collection;
use UncleTioma\JWTAuth\Claims\Expiration;
use UncleTioma\JWTAuth\Claims\IssuedAt;
use UncleTioma\JWTAuth\Claims\Issuer;
use UncleTioma\JWTAuth\Claims\JwtId;
use UncleTioma\JWTAuth\Claims\NotBefore;
use UncleTioma\JWTAuth\Claims\Subject;
use UncleTioma\JWTAuth\Test\AbstractTestCase;

class CollectionTest extends AbstractTestCase
{
    /** @test */
    public function itShouldSanitizeTheClaimsToAssociativeArray()
    {
        $collection = $this->getCollection();

        $this->assertSame(array_keys($collection->toArray()), ['sub', 'iss', 'exp', 'nbf', 'iat', 'jti']);
    }

    private function getCollection()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];

        return new Collection($claims);
    }

    /** @test */
    public function itShouldDetermineIfACollectionContainsAllTheGivenClaims()
    {
        $collection = $this->getCollection();

        $this->assertFalse($collection->hasAllClaims(['sub', 'iss', 'exp', 'nbf', 'iat', 'jti', 'abc']));
        $this->assertFalse($collection->hasAllClaims(['foo', 'bar']));
        $this->assertFalse($collection->hasAllClaims([]));

        $this->assertTrue($collection->hasAllClaims(['sub', 'iss']));
        $this->assertTrue($collection->hasAllClaims(['sub', 'iss', 'exp', 'nbf', 'iat', 'jti']));
    }

    /** @test */
    public function itShouldGetAClaimInstanceByName()
    {
        $collection = $this->getCollection();

        $this->assertInstanceOf(Expiration::class, $collection->getByClaimName('exp'));
        $this->assertInstanceOf(Subject::class, $collection->getByClaimName('sub'));
    }
}
