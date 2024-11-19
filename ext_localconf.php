<?php
declare(strict_types=1);

defined('TYPO3') or die();

(function () {
    $GLOBALS['TYPO3_CONF_VARS']['EXTCONF']['backend']['loginProviders'][1650912385] = [
        'provider' => \DifferentTechnology\AzureAdBe\LoginProvider\ActiveDirectoryLoginProvider::class,
        'sorting' => 100,
        'iconIdentifier' => 'actions-key',
        'label' => 'LLL:EXT:azure_ad_be/Resources/Private/Language/locallang.xlf:login.link'
    ];

    \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addService(
        'azure_ad_be',
        'auth',
        'tx_azure_ad_be',
        [
            'title' => 'Azure AD Authentication',
            'description' => 'Azure AD service for backend',
            'subtype' => 'processLoginDataBE,getUserBE,authUserBE',
            'available' => true,
            'priority' => 100,
            // Must be lower than for \TYPO3\CMS\Sv\AuthenticationService (50) to let other processing take place before
            'quality' => 50,
            'os' => '',
            'exec' => '',
            'className' => \DifferentTechnology\AzureAdBe\Service\AzureAdBeService::class
        ]
    );
})();
