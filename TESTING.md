# Testing Security Headers

The NelmioSecurityBundle provides PHPUnit constraints and a trait to help you test the security headers in your application.

## Installation

The test utilities are included in the bundle. You can use the `SecurityHeadersAssertionsTrait` in your functional tests.

## Basic Usage

The trait allows you to add security header assertions to any test case that extends `WebTestCase`:

```php
<?php

use Nelmio\SecurityBundle\Test\SecurityHeadersAssertionsTrait;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Request;

class HomepageTest extends WebTestCase
{
    use SecurityHeadersAssertionsTrait;

    public function testHomepageHasSecurityHeaders(): void
    {
        $client = static::createClient([], ['HTTPS' => 'on']);
        $client->request(Request::METHOD_GET, '/');

        static::assertIsIsolated();
        static::assertFrameOptions('DENY');
        static::assertContentTypeOptions();
        static::assertReferrerPolicy(['no-referrer', 'strict-origin-when-cross-origin']);
        static::assertStrictTransportSecurity();
        static::assertCspHeader();
    }
}
```

## Available Assertions

### Cross-Origin Isolation

**`assertIsIsolated()`**

Verifies that the response is properly configured for cross-origin isolation, which enables powerful browser features like `SharedArrayBuffer` and high-precision timers.

```php
static::assertIsIsolated();
```

This checks:
- Cross-Origin-Resource-Policy: same-origin
- Cross-Origin-Embedder-Policy: require-corp
- Cross-Origin-Opener-Policy: same-origin

### Individual Header Assertions

**Cross-Origin Headers**

```php
// All cross-origin headers at once (all parameters are required)
static::assertCrossOriginHeaders('same-origin', 'require-corp', 'same-origin');

// Or individually
static::assertCrossOriginResourcePolicy('same-origin');
static::assertCrossOriginEmbedderPolicy('require-corp');
static::assertCrossOriginOpenerPolicy('same-origin');
```

**Frame Options**

```php
static::assertFrameOptions('DENY');
static::assertFrameOptions('SAMEORIGIN');
```

**Content Type Options**

```php
static::assertContentTypeOptions();
```

**Referrer Policy**

```php
static::assertReferrerPolicy(['no-referrer', 'strict-origin-when-cross-origin']);
```

**Strict Transport Security (HSTS)**

```php
// With default values (maxAge=31536000, includeSubDomains=true, preload=true)
static::assertStrictTransportSecurity();

// With custom values
static::assertStrictTransportSecurity(31536000, true, true);
```

**Content Security Policy**

```php
// Check that CSP header exists
static::assertCspHeader();

// Check for specific directives
static::assertCspHeader([
    'default-src',
    'script-src',
    'style-src',
]);

// Check Content-Security-Policy-Report-Only instead
static::assertCspHeader(['default-src', 'script-src'], true);

// Check that CSP contains specific values
static::assertCspHeader(null, false, ["'self'", 'https://cdn.example.com']);

// Check that CSP does NOT contain unsafe values
static::assertCspHeader(null, false, [], ["'unsafe-inline'", "'unsafe-eval'"]);

// Combine all checks: directives, required values, and forbidden values
static::assertCspHeader(
    ['default-src', 'script-src'],  // required directives
    false,                          // not report-only
    ["'self'"],                     // must contain 'self'
    ["'unsafe-inline'"]             // must NOT contain 'unsafe-inline'
);
```

## Advanced Examples

### Testing Multiple Routes

```php
/**
 * @dataProvider routeProvider
 */
public function testSecurityHeadersForAllRoutes(string $route): void
{
    $client = static::createClient([], ['HTTPS' => 'on']);
    $client->request('GET', $route);

    static::assertIsIsolated();
    static::assertFrameOptions('DENY');
    static::assertContentTypeOptions();
}

public static function routeProvider(): iterable
{
    yield 'homepage' => ['/'];
    yield 'about' => ['/about'];
    yield 'contact' => ['/contact'];
}
```

### Testing Different Configurations

```php
public function testApiEndpointHasRelaxedCORP(): void
{
    $client = static::createClient([], ['HTTPS' => 'on']);
    $client->request('GET', '/api/public/data');

    // API might use 'cross-origin' instead of 'same-origin'
    static::assertCrossOriginHeaders('cross-origin', 'require-corp', 'same-origin');
}
```

### Testing CSP Directives

```php
public function testHomepageHasCorrectCSP(): void
{
    $client = static::createClient([], ['HTTPS' => 'on']);
    $client->request('GET', '/');

    // Verify specific CSP directives are present
    static::assertCspHeader([
        'default-src',
        'script-src',
        'style-src',
        'img-src',
        'connect-src',
        'font-src',
    ]);
}

public function testReportOnlyCSP(): void
{
    $client = static::createClient([], ['HTTPS' => 'on']);
    $client->request('GET', '/');

    // Test Content-Security-Policy-Report-Only header
    static::assertCspHeader(['default-src', 'script-src'], true);
}

public function testCspDoesNotAllowUnsafeInline(): void
{
    $client = static::createClient([], ['HTTPS' => 'on']);
    $client->request('GET', '/');

    // Ensure CSP does not contain unsafe values
    static::assertCspHeader(
        ['default-src', 'script-src'],
        false,
        [],
        ["'unsafe-inline'", "'unsafe-eval'"]
    );
}

public function testCspAllowsSpecificCdn(): void
{
    $client = static::createClient([], ['HTTPS' => 'on']);
    $client->request('GET', '/');

    // Ensure CSP allows a specific CDN
    static::assertCspHeader(
        ['script-src'],
        false,
        ['https://cdn.example.com']
    );
}
```

## Custom Constraints

You can also use the constraints directly with PHPUnit's `assertThat()`:

```php
use Nelmio\SecurityBundle\Test\Constraint\ResponseHasCrossOriginResourcePolicy;

$response = $client->getResponse();
static::assertThat(
    $response,
    new ResponseHasCrossOriginResourcePolicy('same-origin')
);
```

### Available Constraints

All constraints are in the `Nelmio\SecurityBundle\Test\Constraint` namespace:

- `ResponseHasCrossOriginResourcePolicy`
- `ResponseHasCrossOriginEmbedderPolicy`
- `ResponseHasCrossOriginOpenerPolicy`
- `ResponseHasFrameOptions`
- `ResponseHasContentTypeOptions`
- `ResponseHasReferrerPolicy`
- `ResponseHasStrictTransportSecurity`
- `ResponseHasContentSecurityPolicy`

## Best Practices

1. **Test all public endpoints**: Ensure security headers are present on all your routes
2. **Test different configurations**: If you have different header configurations for APIs vs frontend, test both
3. **Use data providers**: Test multiple routes efficiently with PHPUnit data providers
4. **Be specific**: Use individual assertions when you need precise control over expected values
