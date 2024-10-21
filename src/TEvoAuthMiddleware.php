<?php

namespace TicketEvolution;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use GuzzleHttp\Psr7\Query;
use GuzzleHttp\Psr7\Uri;

class TEvoAuthMiddleware
{
    /**
     *  API Token
     */
    protected $apiToken;

    /**
     *  API Secret
     */
    protected $apiSecret;

    /**
     * @param string $apiToken
     * @param string $apiSecret
     */
    public function __construct($apiToken, $apiSecret)
    {
        $this->apiToken = $apiToken;
        $this->apiSecret = $apiSecret;
    }

    /**
     * Called when the middleware is handled.
     *
     * @param callable $handler
     *
     * @return \Closure
     */
    public function __invoke(callable $handler)
    {
        return function ($request, array $options) use ($handler) {
            $request = $this->signRequest($request);

            $promise = function (ResponseInterface $response) use ($request) {
                return $response;
            };

            return $handler($request, $options)->then($promise);
        };
    }

    /**
     * Signs the request with the appropriate headers.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return \Psr\Http\Message\RequestInterface
     */
    public function signRequest(RequestInterface $request): RequestInterface
    {
        $request = $this->getRequestWithSortedParameters($request);
        $request = $this->getRequestWithXToken($request);
        return $this->getRequestWithXSignature($request);
    }

    /**
     * Signs the request with the appropriate headers.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return \Psr\Http\Message\RequestInterface
     */
    public function getRequestWithSortedParameters(RequestInterface $request): RequestInterface
    {
        $sortedParams = $this->prepareParameters($this->getParametersFromRequest($request));

        // Use Query::build for the modern version of Guzzle
        $query = Query::build($sortedParams, PHP_QUERY_RFC1738);
        $uri = $request->getUri()->withQuery($query);
        return $request->withUri($uri);
    }

    /**
     * Adds the X-Token header to the request.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return \Psr\Http\Message\RequestInterface
     */
    public function getRequestWithXToken(RequestInterface $request): RequestInterface
    {
        return $request->withHeader('X-Token', $this->apiToken);
    }

    /**
     * Signs the request with the X-Signature header.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return \Psr\Http\Message\RequestInterface
     */
    public function getRequestWithXSignature(RequestInterface $request): RequestInterface
    {
        return $request->withHeader('X-Signature', $this->getSignature($request));
    }

    /**
     * Calculate signature for request
     *
     * @param RequestInterface $request Request to generate a signature for
     *
     * @return string
     */
    public function getSignature(RequestInterface $request): string
    {
        $stringToSign = $this->getStringToSign($request);

        return base64_encode($this->signHmacSha256($stringToSign));
    }

    /**
     * Calculate signature for request
     *
     * @param RequestInterface $request Request to generate a signature for
     *
     * @return string
     */
    public function getStringToSign(RequestInterface $request): string
    {
        // For POST|PUT set the JSON body string as the params
        if (in_array($request->getMethod(), ['POST', 'PUT', 'PATCH'])) {
            $data = $request->getBody()->__toString();
        } else {
            $data = $this->getParametersFromRequest($request);
        }

        return $this->createBaseString(
                $request,
                $data
        );
    }

    /**
     * Creates the Signature Base String.
     *
     * The Signature Base String is a consistent reproducible concatenation of
     * the request elements into a single string. The string is used as an
     * input in hashing or signing algorithms.
     *
     * @param RequestInterface $request Request being signed
     * @param array|string    $data    HTTP Request parameters
     *
     * @return string Returns the base string
     */
    protected function createBaseString(RequestInterface $request, $data = []): string
    {
        // Use Uri for safer URL manipulation
        $uri = new Uri((string) $request->getUri());
        $url = preg_replace('/https:\/\/|\?.*/', '', (string) $uri);

        if (is_array($data)) {
            $query = http_build_query($data, '', '&', PHP_QUERY_RFC1738);
        } else {
            $query = $data;
        }

        return strtoupper($request->getMethod())
                . ' ' . $url
                . '?' . $query;
    }

    /**
     * Sorts the array and removes null parameters
     *
     * @param array $params Data array
     *
     * @return array
     */
    private function prepareParameters($params): array
    {
        // Parameters are sorted by name, using lexicographical byte value ordering.
        uksort($params, 'strcmp');

        // Unset any parameters with null values
        return array_filter($params, static function ($value) {
            return $value !== null;
        });
    }

    /**
     * Perform the HMAC SHA256 signing using the $apiSecret
     *
     * @param $baseString
     *
     * @return string
     */
    private function signHmacSha256($baseString): string
    {
        return hash_hmac('sha256', $baseString, $this->apiSecret, true);
    }

    /**
     * @param RequestInterface $request
     *
     * @return array
     */
    protected function getParametersFromRequest(RequestInterface $request): array
    {
        $uri = $request->getUri();
        // Use Query::parse for the modern version of Guzzle
        return Query::parse($uri->getQuery(), PHP_QUERY_RFC1738);
    }
}
