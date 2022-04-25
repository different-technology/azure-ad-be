<?php

declare(strict_types=1);

namespace DifferentTechnology\AzureAdBe\Service;

use Doctrine\DBAL\Driver\Exception;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessTokenInterface;
use TYPO3\CMS\Core\Authentication\AbstractUserAuthentication;
use TYPO3\CMS\Core\Crypto\PasswordHashing\InvalidPasswordHashException;
use TYPO3\CMS\Core\Crypto\Random;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Service\AbstractService;
use TYPO3\CMS\Core\SingletonInterface;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Utility\HttpUtility;
use TYPO3\CMS\Extbase\Configuration\ConfigurationManager;
use TYPO3\CMS\Core\Crypto\PasswordHashing\PasswordHashFactory;

class AzureAdBeService extends AbstractService implements SingletonInterface
{
    /**
     * Login data as passed to initAuth()
     *
     * @var array
     */
    protected array $loginData = [];

    /**
     * Additional authentication information provided by AbstractUserAuthentication.
     * We use it to decide what database table contains user records.
     *
     * @var array
     */
    protected array $authenticationInformation = [];

    protected string $loginIdentifier = '';

    protected string $userName = '';

    /**
     * @var AccessTokenInterface
     */
    protected AccessTokenInterface $accessToken;

    /**
     * Checks if service is available. In this case only in BE-Context
     * @return bool TRUE if service is available
     */
    public function init(): bool
    {
        return (TYPO3_MODE === 'BE') && parent::init();
    }

    /**
     * Initializes authentication for this service.
     *
     * @param string $subType Subtype for authentication (either "getUserFE" or "getUserBE")
     * @param array $loginData Login data submitted by user and preprocessed by AbstractUserAuthentication
     * @param array $authenticationInformation Additional TYPO3 information for authentication services (unused here)
     * @param AbstractUserAuthentication $parentObject Calling object
     * @return void
     */
    public function initAuth(
        string $subType,
        array $loginData,
        array $authenticationInformation,
        AbstractUserAuthentication $parentObject
    ) {
        $this->loginData = $loginData;
        $this->authenticationInformation = $authenticationInformation;
    }

    /**
     * Process the submitted login identifier if valid.
     *
     * @param array $loginData Credentials that are submitted and potentially modified by other services
     * @param string $passwordTransmissionStrategy Keyword of how the password has been hashed or encrypted before submission
     * @return bool
     */
    public function processLoginData(array &$loginData, string $passwordTransmissionStrategy): bool
    {
        // Pre-process the login only if no password has been submitted
        if (empty($loginData['uident'])) {
            $this->initializeSession();
            $authorizationCode = GeneralUtility::_GP('code');
            $oAuthProvider = $this->getOAuthProvider($this->getReturnURL());
            if (!$authorizationCode) {
                $email = GeneralUtility::_POST('ad_email');
                $authorizationUrl = $oAuthProvider->getAuthorizationUrl([
                    'login_hint' => $email,
                ]);
                $_SESSION['state'] = $oAuthProvider->getState();
                HttpUtility::redirect($authorizationUrl);
            } else {
                $state = GeneralUtility::_GP('state');

                if (!$state || $state !== $_SESSION['state']) {
                    $this->destroySession();
                    return false;
                }

                try {
                    $this->accessToken = $oAuthProvider->getAccessToken('authorization_code', [
                        'code' => $authorizationCode,
                    ]);
                } catch (IdentityProviderException $exception) {
                    return false;
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
                    return false;
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
        $returnURL = rtrim(GeneralUtility::getIndpEnv('TYPO3_SITE_URL'), '/') . '/' . TYPO3_mainDir . '?login_status=login';
        return GeneralUtility::locationHeaderUrl($returnURL);
    }

    private function getOAuthProvider(string $returnUrl): GenericProvider
    {
        return new GenericProvider([
            'clientId' => $_ENV['TYPO3_AZURE_AD_BE_CLIENT_ID'],
            'clientSecret' => $_ENV['TYPO3_AZURE_AD_BE_CLIENT_SECRET'],
            'redirectUri' => $returnUrl,
            'urlAuthorize' => $_ENV['TYPO3_AZURE_AD_BE_URL_AUTHORIZE'],
            'urlAccessToken' => $_ENV['TYPO3_AZURE_AD_BE_URL_ACCESS_TOKEN'],
            'urlResourceOwnerDetails' => '',
            'scopes' => 'User.Read profile openid email',
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
        if ($this->loginData['status'] !== 'login' || $this->loginIdentifier === '') {
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
            ->getQueryBuilderForTable($this->authenticationInformation['db_user']['table']);
        $queryBuilder->getRestrictions()->removeAll();
        return $queryBuilder
            ->select('*')
            ->from($this->authenticationInformation['db_user']['table'])
            ->where(
                $queryBuilder->expr()->eq(
                    'username',
                    $queryBuilder->createNamedParameter(
                        $this->loginIdentifier,
                        Connection::PARAM_STR
                    )
                ),
                $this->authenticationInformation['db_user']['check_pid_clause'],
                $this->authenticationInformation['db_user']['enable_clause']
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
            ->getConnectionForTable($this->authenticationInformation['db_user']['table']);

        if ($job === 'insert') {
            $userFields['username'] = $this->loginIdentifier;
            $userFields['email'] = $this->loginIdentifier;
            $userFields['password'] = $this->generateHashedPassword();
            $userFields['admin'] = 0;
            $userFields['crdate'] = $GLOBALS['EXEC_TIME'];
            $databaseConnection->insert($this->authenticationInformation['db_user']['table'], $userFields);
        } else {
            $databaseConnection->update(
                $this->authenticationInformation['db_user']['table'],
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

}
