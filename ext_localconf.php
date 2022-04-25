<?php
if (!defined('TYPO3_MODE')) {
    die('Access denied.');
}

new class() {

    public function __construct()
    {
        if (TYPO3_MODE === 'BE') {
            $GLOBALS['TYPO3_CONF_VARS']['EXTCONF']['backend']['loginProviders'][1650912385] = [
                'provider' => \DifferentTechnology\AzureAdBe\LoginProvider\ActiveDirectoryLoginProvider::class,
                'sorting' => 100,
                'icon-class' => 'fa-key',
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
        }
    }
};
