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

namespace UncleTioma\JWTAuth\Test;

use Mockery;
use Mockery\LegacyMockInterface;
use UncleTioma\JWTAuth\Blacklist;
use UncleTioma\JWTAuth\Claims\Collection;
use UncleTioma\JWTAuth\Claims\Expiration;
use UncleTioma\JWTAuth\Claims\IssuedAt;
use UncleTioma\JWTAuth\Claims\Issuer;
use UncleTioma\JWTAuth\Claims\JwtId;
use UncleTioma\JWTAuth\Claims\NotBefore;
use UncleTioma\JWTAuth\Claims\Subject;
use UncleTioma\JWTAuth\Contracts\Providers\JWT;
use UncleTioma\JWTAuth\Exceptions\InvalidClaimException;
use UncleTioma\JWTAuth\Exceptions\JWTException;
use UncleTioma\JWTAuth\Exceptions\TokenBlacklistedException;
use UncleTioma\JWTAuth\Factory;
use UncleTioma\JWTAuth\Manager;
use UncleTioma\JWTAuth\Payload;
use UncleTioma\JWTAuth\Token;
use UncleTioma\JWTAuth\Validators\PayloadValidator;

class ManagerTest extends AbstractTestCase
{
    protected LegacyMockInterface $jwt;

    protected LegacyMockInterface $blacklist;

    protected LegacyMockInterface $factory;

    protected Manager $manager;

    protected LegacyMockInterface $validator;

    public function setUp(): void
    {
        parent::setUp();

        $this->jwt = Mockery::mock(JWT::class);
        $this->blacklist = Mockery::mock(Blacklist::class);
        $this->factory = Mockery::mock(Factory::class);
        $this->manager = new Manager($this->jwt, $this->blacklist, $this->factory);
        $this->validator = Mockery::mock(PayloadValidator::class);
    }

    /** @test
     * @throws InvalidClaimException
     */
    public function itShouldEncodeAPayload()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);

        $this->jwt->shouldReceive('encode')->with($payload->toArray())->andReturn('foo.bar.baz');

        $token = $this->manager->encode($payload);

        $this->assertEquals($token, 'foo.bar.baz');
    }

    /** @test
     * @throws InvalidClaimException|TokenBlacklistedException
     */
    public function itShouldDecodeAToken()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);

        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());

        $this->factory->shouldReceive('setRefreshFlow')->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(false);

        $payload = $this->manager->decode($token);

        $this->assertInstanceOf(Payload::class, $payload);
        $this->assertSame($payload->count(), 6);
    }

    /** @test
     * @throws InvalidClaimException
     */
    public function itShouldThrowExceptionWhenTokenIsBlacklisted()
    {
        $this->expectException(TokenBlacklistedException::class);
        $this->expectExceptionMessage('The token has been blacklisted');

        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());

        $this->factory->shouldReceive('setRefreshFlow')->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->with($payload->toArray())->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(true);

        $this->manager->decode($token);
    }

    /** @test
     * @throws InvalidClaimException
     */
    public function itShouldRefreshAToken()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp - 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->twice()->with('foo.bar.baz')->andReturn($payload->toArray());
        $this->jwt->shouldReceive('encode')->with($payload->toArray())->andReturn('baz.bar.foo');

        $this->factory->shouldReceive('setRefreshFlow')->with(true)->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(false);
        $this->blacklist->shouldReceive('add')->once()->with($payload);

        $token = $this->manager->refresh($token);

        // $this->assertArrayHasKey('ref', $payload);
        $this->assertInstanceOf(Token::class, $token);
        $this->assertEquals('baz.bar.foo', $token);
    }

    /** @test
     * @throws InvalidClaimException
     */
    public function itShouldInvalidateAToken()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());

        $this->factory->shouldReceive('setRefreshFlow')->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->with($payload->toArray())->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(false);

        $this->blacklist->shouldReceive('add')->with($payload)->andReturn(true);

        $this->manager->invalidate($token);
    }

    /** @test
     * @throws InvalidClaimException
     */
    public function itShouldForceInvalidateATokenForever()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $this->validator->shouldReceive('setRefreshFlow->check')->andReturn($collection);
        $payload = new Payload($collection, $this->validator);
        $token = new Token('foo.bar.baz');

        $this->jwt->shouldReceive('decode')->once()->with('foo.bar.baz')->andReturn($payload->toArray());

        $this->factory->shouldReceive('setRefreshFlow')->andReturn($this->factory);
        $this->factory->shouldReceive('customClaims')->with($payload->toArray())->andReturn($this->factory);
        $this->factory->shouldReceive('make')->andReturn($payload);

        $this->blacklist->shouldReceive('has')->with($payload)->andReturn(false);

        $this->blacklist->shouldReceive('addForever')->with($payload)->andReturn(true);

        $this->manager->invalidate($token, true);
    }

    /** @test */
    public function itShouldThrowAnExceptionWhenEnableBlacklistIsSetToFalse()
    {
        $this->expectException(JWTException::class);
        $this->expectExceptionMessage('You must have the blacklist enabled to invalidate a token.');

        $token = new Token('foo.bar.baz');

        $this->manager->setBlacklistEnabled(false)->invalidate($token);
    }

    /** @test */
    public function itShouldGetThePayloadFactory()
    {
        $this->assertInstanceOf(Factory::class, $this->manager->getPayloadFactory());
    }

    /** @test */
    public function itShouldGetTheJwtProvider()
    {
        $this->assertInstanceOf(JWT::class, $this->manager->getJWTProvider());
    }

    /** @test */
    public function itShouldGetTheBlacklist()
    {
        $this->assertInstanceOf(Blacklist::class, $this->manager->getBlacklist());
    }

    /** @test */
    public function testIfShowBlacklistedExceptionConfigurationIsEnabled()
    {
        $this->manager->setBlackListExceptionEnabled(true);

        $this->assertIsBool($this->manager->getBlackListExceptionEnabled());
    }

    /** @test */
    public function testIfBlackListedExceptionIsSetToTrue()
    {
        $this->manager->setBlackListExceptionEnabled(true);

        $this->assertTrue($this->manager->getBlackListExceptionEnabled());
    }

    /** @test */
    public function testIfBlackListedExceptionIsSetToFalse()
    {
        $this->manager->setBlackListExceptionEnabled(false);

        $this->assertFalse($this->manager->getBlackListExceptionEnabled());
    }
}
