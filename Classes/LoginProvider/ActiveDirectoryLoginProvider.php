<?php

declare(strict_types=1);

namespace DifferentTechnology\AzureAdBe\LoginProvider;

use TYPO3\CMS\Backend\Controller\LoginController;
use TYPO3\CMS\Backend\LoginProvider\LoginProviderInterface;
use TYPO3\CMS\Core\Page\PageRenderer;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Fluid\View\StandaloneView;

class ActiveDirectoryLoginProvider implements LoginProviderInterface
{
    /**
     * @param StandaloneView $view
     * @param PageRenderer $pageRenderer
     * @param LoginController $loginController
     * @throws \UnexpectedValueException
     */
    public function render(StandaloneView $view, PageRenderer $pageRenderer, LoginController $loginController)
    {
        $view->setTemplatePathAndFilename(GeneralUtility::getFileAbsFileName('EXT:azure_ad_be/Resources/Private/Templates/LoginForm.html'));
    }
}
