<?php

declare(strict_types=1);

namespace DifferentTechnology\AzureAdBe\Service;

use Doctrine\DBAL\Driver\Exception;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessTokenInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Log\LoggerAwareTrait;
use TYPO3\CMS\Core\Authentication\AbstractAuthenticationService;
use TYPO3\CMS\Core\Authentication\Event\BeforeRequestTokenProcessedEvent;
use TYPO3\CMS\Core\Crypto\PasswordHashing\InvalidPasswordHashException;
use TYPO3\CMS\Core\Crypto\PasswordHashing\PasswordHashFactory;
use TYPO3\CMS\Core\Crypto\Random;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Http\PropagateResponseException;
use TYPO3\CMS\Core\Security\RequestToken;
use TYPO3\CMS\Core\Service\AbstractService;
use TYPO3\CMS\Core\SingletonInterface;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Extbase\Configuration\ConfigurationManager;

class AzureAdBeService extends AbstractAuthenticationService implements SingletonInterface
{
    use LoggerAwareTrait;

    protected string $loginIdentifier = '';

    protected string $userName = '';

    protected AccessTokenInterface $accessToken;

    protected GenericProvider $oAuthProvider;

    protected ResponseFactoryInterface $responseFactory;

    public function injectResponseFactory(ResponseFactoryInterface $responseFactory)
    {
        $this->responseFactory = $responseFactory;
    }

    /**
     * Process the submitted login identifier if valid.
     *
     * @param array $loginData Credentials that are submitted and potentially modified by other services
     * @param string $passwordTransmissionStrategy Keyword of how the password has been hashed or encrypted before submission
     * @return bool
     * @throws \Exception
     */
    public function processLoginData(array &$loginData, string $passwordTransmissionStrategy): bool
    {
        // Pre-process the login only if no password has been submitted
        if (empty($loginData['uident'])) {
            $this->initializeSession();
            $authorizationCode = $_GET['code']; // no request available at this point
            $this->oAuthProvider = $this->getOAuthProvider($this->getReturnURL());
            if (!$authorizationCode) {
                $email = $_POST['ad_email']; // no request available at this point
                $authorizationUrl = $this->oAuthProvider->getAuthorizationUrl([
                    'login_hint' => $email,
                ]);
                $_SESSION['state'] = $this->oAuthProvider->getState();
                $response = $this->responseFactory
                    ->createResponse(303)
                    ->withAddedHeader('location', $authorizationUrl);
                throw new PropagateResponseException($response);
            } else {
                $state = $_GET['state']; // no request available at this point

                if (!$state || $state !== $_SESSION['state']) {
                    $this->destroySession();
                    return false;
                }

                try {
                    $this->accessToken = $this->oAuthProvider->getAccessToken('authorization_code', [
                        'code' => $authorizationCode,
                    ]);

                } catch (IdentityProviderException $exception) {
                    if ($exception->getMessage() === 'invalid_client') {
                        $exception = new \Exception(
                            '"invalid_client" - You may have to refresh your client secret. ' .
                            'Please visit ' .
                            'https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/' .
                            $_ENV['TYPO3_AZURE_AD_BE_CLIENT_ID'],
                            1714651325,
                            $exception
                        );
                    }

                    $this->logger->error(
                        $exception->getMessage(),
                        (array)$exception
                    );

                    throw $exception;
                }


                // The id token is a JWT token that contains information about the user
                // It's a base64 coded string that has a header, payload and signature
                $idToken = $this->accessToken->getValues()['id_token'];
                $decodedAccessTokenPayload = base64_decode(
                    explode('.', $idToken)[1]
                );

                $jsonAccessTokenPayload = json_decode($decodedAccessTokenPayload, true);
                $emailAddress = $jsonAccessTokenPayload['preferred_username'] ?? null;

                if ($emailAddress === null) {
                    throw new \Exception('No email address in Entra ID profile', 1714651326);
                }

                $this->loginIdentifier = strtolower($emailAddress);
                $this->userName = $jsonAccessTokenPayload['name'];
                return true;
            }
        }
        return false;
    }

    private function initializeSession()
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    private function destroySession()
    {
        if (session_status() !== PHP_SESSION_NONE) {
            session_destroy();
        }
    }


    /**
     * Creates return URL for the oAuth server. When a user is authenticated by
     * the oAuth server, the user will be sent to this URL to complete
     * authentication process with the current site. We send it to our script.
     *
     * @return string Return URL
     */
    protected function getReturnURL(): string
    {
        // In the Backend we will use dedicated script to create session.
        // It is much easier for the Backend to manage users.
        // Notice: 'login_status' parameter name cannot be changed!
        // It is essential for BE user authentication.

        /** @var ConfigurationManager $configurationManager */
        $returnURL = rtrim(GeneralUtility::getIndpEnv('TYPO3_SITE_URL'), '/') . '/typo3/?login_status=login';
        return GeneralUtility::locationHeaderUrl($returnURL);
    }

    private function getOAuthProvider(string $returnUrl): GenericProvider
    {
        $scopes = ['User.Read', 'profile', 'openid', 'email'];
        if(isset($GLOBALS['TYPO3_CONF_VARS']['EXTCONF']['azure_ad_be']['groups'])) {
            $scopes[] = 'Directory.Read.All';
        }
        return new GenericProvider([
            'clientId' => $_ENV['TYPO3_AZURE_AD_BE_CLIENT_ID'],
            'clientSecret' => $_ENV['TYPO3_AZURE_AD_BE_CLIENT_SECRET'],
            'redirectUri' => $returnUrl,
            'urlAuthorize' => $_ENV['TYPO3_AZURE_AD_BE_URL_AUTHORIZE'],
            'urlAccessToken' => $_ENV['TYPO3_AZURE_AD_BE_URL_ACCESS_TOKEN'],
            'urlResourceOwnerDetails' => '',
            'scopes' => implode(' ', $scopes),
        ]);
    }

    /**
     * This function returns the user record back to the AbstractUserAuthentication.
     * It does not mean that user is authenticated, it means only that user is found. This
     * function makes sure that the user cannot be authenticated by any other service
     * if user tries to use SSO to authenticate.
     *
     * @return array|false User record (content of be_users as appropriate for the current mode)
     * @throws Exception
     * @throws InvalidPasswordHashException
     */
    public function getUser()
    {
        if ($this->login['status'] !== 'login' || $this->loginIdentifier === '') {
            return null;
        }
        $user = $this->getUserRecord();
        if ($user === false) {
            $this->createOrUpdateUserRecord('insert');
        } else {
            $this->createOrUpdateUserRecord('update');
        }
        return $this->getUserRecord();
    }

    /**
     * Authenticates user
     *
     * Login is allowed for all users (but no groups / permissions are initially assigned)
     *
     * @param array $userRecord User record
     * @return int Code that shows if user is really authenticated.
     */
    public function authUser(array $userRecord): int
    {
        if ($this->loginIdentifier === '') {
            return 100;
        }

        return 300;

//        return -100; // login not allowed
    }

    /**
     * @return false|array
     * @throws Exception
     */
    protected function getUserRecord()
    {
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)
            ->getQueryBuilderForTable($this->authInfo['db_user']['table']);
        $queryBuilder->getRestrictions()->removeAll();
        return $queryBuilder
            ->select('*')
            ->from($this->authInfo['db_user']['table'])
            ->where(
                $queryBuilder->expr()->eq(
                    'username',
                    $queryBuilder->createNamedParameter(
                        $this->loginIdentifier,
                        Connection::PARAM_STR
                    )
                ),
                $this->authInfo['db_user']['check_pid_clause'],
                $this->authInfo['db_user']['enable_clause']
            )
            ->execute()
            ->fetchAssociative();
    }

    /**
     * @throws InvalidPasswordHashException
     */
    private function createOrUpdateUserRecord(string $job)
    {
        $userFields = [
            'realName' => $this->userName ?? '',
            'tstamp' => $GLOBALS['EXEC_TIME'],
        ];
        $databaseConnection = GeneralUtility::makeInstance(ConnectionPool::class)
            ->getConnectionForTable($this->authInfo['db_user']['table']);

        if ($job === 'insert') {
            $userFields['username'] = $this->loginIdentifier;
            $userFields['email'] = $this->loginIdentifier;
            $userFields['password'] = $this->generateHashedPassword();
            $userFields['admin'] = 0;
            $userFields['crdate'] = $GLOBALS['EXEC_TIME'];

            $EXTCONF = $GLOBALS['TYPO3_CONF_VARS']['EXTCONF']['azure_ad_be'];
            if(isset($EXTCONF['groups']) && is_array($EXTCONF['groups'])) {
                $request  = $this->oAuthProvider->getAuthenticatedRequest(
                    'get',
                    'https://graph.microsoft.com/v1.0/me/memberOf',
                    $this->accessToken,
                    []
                );
                $groups = $this->oAuthProvider->getParsedResponse($request);
                foreach($groups['value'] as $group) {
                    if(isset($EXTCONF['groups'][$group['displayName']])) {
                        $userFields = array_merge($userFields, $EXTCONF['groups'][$group['displayName']]);
                    }
                }
            }

            $databaseConnection->insert($this->authInfo['db_user']['table'], $userFields);
        } else {
            $databaseConnection->update(
                $this->authInfo['db_user']['table'],
                $userFields,
                ['username' => $this->loginIdentifier]
            );
        }
    }

    /**
     * @throws InvalidPasswordHashException
     */
    protected function generateHashedPassword(): string
    {
        $cryptoService = GeneralUtility::makeInstance(Random::class);
        $password = $cryptoService->generateRandomBytes(20);
        $passwordHashFactory = GeneralUtility::makeInstance(PasswordHashFactory::class);
        $saltFactory = $passwordHashFactory->getDefaultHashInstance('BE');
        return $saltFactory->getHashedPassword($password);
    }

    /**
     * EventListener (Hook) to validate the SSO redirected URL
     *
     * @param BeforeRequestTokenProcessedEvent $event
     * @return void
     */
    public function handleEvent(BeforeRequestTokenProcessedEvent $event)
    {
        $requestToken = $event->getRequestToken();
        // fine, there is a valid request-token
        if ($requestToken instanceof RequestToken) {
            return;
        }

        // check if login request is a valid URL
        $params = $event->getRequest()->getQueryParams();
        if (
            count($params) === 4
            && $params['login_status'] === 'login'
            && !empty($params['code'])
            && !empty($params['state'])
            && !empty($params['session_state'])
        ) {
            // set URL token as valid
            $event->setRequestToken(
                RequestToken::create('core/user-auth/' . strtolower($event->getUser()->loginType))
            );
        }
    }
}
