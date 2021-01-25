<?php

namespace Overtrue\Socialite\Providers;

use GuzzleHttp\ClientInterface;
use Overtrue\Socialite\ProviderInterface;
use Overtrue\Socialite\User;

/**
 * @see https://opendocs.alipay.com/open/289/105656
 */
class AlipayProvider extends AbstractProvider implements ProviderInterface
{
    protected $baseUrl = 'https://openapi.alipay.com/gateway.do';

    protected $scopes = ['auth_user'];

    protected $apiVersion = '1.0';

    protected $signType = 'RSA2';

    protected $postCharset = 'UTF-8';

    protected $format = 'json';

    protected $stateless = true;

    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase('https://openauth.alipay.com/oauth2/publicAppAuthorize.htm', $state);
    }

    protected function getCode()
    {
        return $this->request->get('auth_code');
    }

    protected function getCodeFields($state = null)
    {
        $fields = array_merge([
            'app_id' => $this->getConfig()->get('client_id'),
            'redirect_uri' => $this->redirectUrl,
            'scope' => $this->formatScopes($this->scopes, $this->scopeSeparator),
            'response_type' => 'code',
        ], $this->parameters);

        if ($this->usesState()) {
            $fields['state'] = $state;
        }

        return $fields;
    }

    /**
     * @param string $code
     * @return \Overtrue\Socialite\AccessTokenInterface
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getAccessToken($code)
    {
        if ($this->accessToken) {
            return $this->accessToken;
        }
        $guzzleVersion = \defined(ClientInterface::class.'::VERSION') ? \constant(ClientInterface::class.'::VERSION') : 7;

        $postKey = (1 === version_compare($guzzleVersion, '6')) ? 'form_params' : 'body';

        $responseRaw = $this->getHttpClient()->post($this->getTokenUrl(), [
            'headers' => ['Accept' => 'application/json'],
            $postKey => $this->getTokenFields($code),
        ]);

        $response = json_decode($responseRaw->getBody()->getContents(), true);
        $responseRaw->getBody()->seek(0);

        if (!empty($response['error_response']) || empty($response['alipay_system_oauth_token_response'])) {
            throw new \InvalidArgumentException('You have getAccessToken error! ' . $responseRaw->getBody());
        }

        return $this->parseAccessToken($response['alipay_system_oauth_token_response']);
    }

    protected function getTokenFields($code)
    {
        $params = $this->getPublicFields('alipay.system.oauth.token');
        $params += [
            'code' => $code,
            'grant_type' => 'authorization_code',
        ];
        $params['sign'] = $this->generateSign($params);

        return $params;
    }

    protected function getTokenUrl()
    {
        return $this->baseUrl;
    }

    /**
     * @param \Overtrue\Socialite\AccessTokenInterface $token
     * @return array
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getUserByToken($token)
    {
        $params = $this->getPublicFields('alipay.user.info.share');
        $params += ['auth_token' => $token->getToken()];
        $params['sign'] = $this->generateSign($params);

        $responseRaw = $this->getHttpClient()->post(
            $this->baseUrl,
            [
                'form_params' => $params,
                'headers' => [
                    "content-type" => "application/x-www-form-urlencoded;charset=utf-8",
                ],
            ]
        );

        $response = json_decode($responseRaw->getBody()->getContents(), true);
        $responseRaw->getBody()->seek(0);

        if (!empty($response['error_response']) || empty($response['alipay_user_info_share_response']['user_id'])) {
            throw new \InvalidArgumentException('You have getUserByToken error! response :' . $responseRaw->getBody() . ' | request' . json_encode($params, JSON_UNESCAPED_UNICODE));
        }

        return $response['alipay_user_info_share_response'];
    }

    /**
     * @param array $user
     * @return User
     */
    protected function mapUserToObject(array $user)
    {
        return new User(
            [
                'id' => $user['user_id'] ?? null,
                'name' => $user['nick_name'] ?? null,
                'nickname' => $user['nick_name'] ?? null,
                'avatar' => $user['avatar'] ?? null,
                'email' => $user['email'] ?? null,
            ]
        );
    }

    /**
     * @param $code
     * @return mixed
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function tokenFromCode($code)
    {
        $response = $this->getHttpClient()->post(
            $this->getTokenUrl(),
            [
                'form_params' => $this->getTokenFields($code),
                'headers' => [
                    "content-type" => "application/x-www-form-urlencoded;charset=utf-8",
                ],
            ]
        );
        $response = json_decode($response->getBody()->getContents(), true);

        if (!empty($response['error_response'])) {
            throw new \InvalidArgumentException('You have error! ' . json_encode($response, JSON_UNESCAPED_UNICODE));
        }
        $response = $response['alipay_system_oauth_token_response'];
        return $response['access_token'];
    }


    /**
     * @param $code
     * @return mixed
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function infoFromCode($code)
    {
        $response = $this->getHttpClient()->post(
            $this->getTokenUrl(),
            [
                'form_params' => $this->getTokenFields($code),
                'headers' => [
                    "content-type" => "application/x-www-form-urlencoded;charset=utf-8",
                ],
            ]
        );
        $response = json_decode($response->getBody()->getContents(), true);

        if (!empty($response['error_response'])) {
            throw new \InvalidArgumentException('You have error! ' . json_encode($response, JSON_UNESCAPED_UNICODE));
        }

        return $response['alipay_system_oauth_token_response'];
    }



    /**
     * @param string $method
     *
     * @return array
     */
    public function getPublicFields($method)
    {
        return [
            'app_id' => $this->getConfig()->get('client_id'),
            'format' => $this->format,
            'charset' => $this->postCharset,
            'sign_type' => $this->signType,
            'method' => $method,
            'timestamp' => date('Y-m-d H:m:s'),
            'version' => $this->apiVersion,
        ];
    }

    /**
     * @param $params
     * @return string
     * @see https://opendocs.alipay.com/open/289/105656
     */
    protected function generateSign($params)
    {
        ksort($params);

        $signContent = $this->buildParams($params);
        $key = $this->getConfig()->get('rsa_private_key');
        $signValue = $this->signWithSHA256RSA($signContent, $key);

        return $signValue;
    }

    /**
     * @param string $signContent
     * @param string $key
     *
     * @return string
     */
    protected function signWithSHA256RSA($signContent, $key)
    {
        if (empty($key)) {
            throw new \InvalidArgumentException('no RSA private key set.');
        }

        $key = "-----BEGIN RSA PRIVATE KEY-----\n" .
            chunk_split($key, 64, "\n") .
            "-----END RSA PRIVATE KEY-----";

        openssl_sign($signContent, $signValue, $key, OPENSSL_ALGO_SHA256);

        return base64_encode($signValue);
    }

    /**
     * @param array          $params
     * @param bool           $urlencode
     * @param array|string[] $except
     *
     * @return string
     */
    public static function buildParams(array $params, $urlencode = false, array $except = ['sign'])
    {
        $param_str = '';
        foreach ($params as $k => $v) {
            if (in_array($k, $except)) {
                continue;
            }
            $param_str .= $k . '=';
            $param_str .= $urlencode ? rawurlencode($v) : $v;
            $param_str .= '&';
        }

        return rtrim($param_str, '&');
    }
}
