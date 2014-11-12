<?php

namespace League\OAuth2\Client\Provider;

use League\OAuth2\Client\Entity\User;
use Guzzle\Http\Message\Request as HttpRequest;

class Yammer extends AbstractProvider
{
    public $method = 'get';

    public $headers = array(
        'Authorization' => 'Bearer ');

    public function urlAuthorize()
    {
        return 'https://www.yammer.com/dialog/oauth';
    }

    public function urlAccessToken()
    {
        return 'https://www.yammer.com/oauth2/access_token.json';
    }

    public function urlUserDetails(\League\OAuth2\Client\Token\AccessToken $token)
    {
        $this->headers = array(
            'Authorization' => 'Bearer ' . $token->__toString());

        return 'https://www.yammer.com/api/v1/users/current.json';
    }

    public function userDetails($response, \League\OAuth2\Client\Token\AccessToken $token)
    {
        $response = (array) $response;

        $user = new User;

        $imageUrl = (isset($response['picture'])) ? $response['picture'] : null;

        $emailAddressesArray = $response['contact']->email_addresses;
        $email = '';
        foreach($emailAddressesArray as $emailObject) {
            if ($emailObject->type == 'primary') {
                $email = $emailObject->address;
            }
        }

        $user->exchangeArray(array(
            'uid' => $response['id'],
            'name' => $response['full_name'],
            'firstname' => $response['first_name'],
            'lastName' => $response['last_name'],
            'email' => $email,
            'imageUrl' => $imageUrl,
            'network_domains' => $response['network_domains']
        ));

        return $user;
    }

    public function userUid($response, \League\OAuth2\Client\Token\AccessToken $token)
    {
        return $response->id;
    }

    public function userEmail($response, \League\OAuth2\Client\Token\AccessToken $token)
    {
        return isset($response->email) && $response->email ? $response->email : null;
    }

    public function userScreenName($response, \League\OAuth2\Client\Token\AccessToken $token)
    {
        return array($response->given_name, $response->family_name);
    }

    /**
     *  Custom getAccessToken, since the parent class one doesn't expect Yammer style GET and responses
     *
     */
    public function getAccessToken($grant = 'authorization_code', $params = array())
    {
        if (is_string($grant)) {
            // PascalCase the grant. E.g: 'authorization_code' becomes 'AuthorizationCode'
            $className = str_replace(' ', '', ucwords(str_replace(array('-', '_'), ' ', $grant)));
            $grant = 'League\\OAuth2\\Client\\Grant\\'.$className;
            if (! class_exists($grant)) {
                throw new \InvalidArgumentException('Unknown grant "'.$grant.'"');
            }
            $grant = new $grant;
        } elseif (! $grant instanceof GrantInterface) {
            $message = get_class($grant).' is not an instance of League\OAuth2\Client\Grant\GrantInterface';
            throw new \InvalidArgumentException($message);
        }

        $defaultParams = array(
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri'  => $this->redirectUri,
            'grant_type'    => $grant,
        );

        $requestParams = $grant->prepRequestParams($defaultParams, $params);

        try {
            $client = $this->getHttpClient();
            $client->setBaseUrl($this->urlAccessToken() . '?' . $this->httpBuildQuery($requestParams, '', '&'));
            $request = $client->send(new HttpRequest($this->method, $client->getBaseUrl()));
            $response = $request->getBody();    
        } catch (BadResponseException $e) {
            // @codeCoverageIgnoreStart
            $raw_response = explode("\n", $e->getResponse());
            $response = end($raw_response);
            // @codeCoverageIgnoreEnd
        }

        $result = json_decode($response, true);
        
        if (isset($result['error']) && ! empty($result['error'])) {
            // @codeCoverageIgnoreStart
            throw new IDPException($result);
            // @codeCoverageIgnoreEnd
        }

        return $grant->handleResponse($result);
    }
}
