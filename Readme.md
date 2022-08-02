# Azure Active Directory - TYPO3 Backend Login

## Setup

Add the following env parameters:

```
TYPO3_AZURE_AD_BE_CLIENT_ID=<your-client-id>
TYPO3_AZURE_AD_BE_CLIENT_SECRET=<your-secret>
TYPO3_AZURE_AD_BE_URL_AUTHORIZE=https://login.microsoftonline.com/<see-your-endpoints>/oauth2/v2.0/authorize
TYPO3_AZURE_AD_BE_URL_ACCESS_TOKEN=https://login.microsoftonline.com/<see-your-endpoints>/oauth2/v2.0/token
```

### Group permissions

You may wish to affect the users permissions or properties depending on which Azure AD group they are in.

Ensure your application has `Directory.Read.All` permissions.

In your site_package `ext_localconf.php`, create an array where the group display name is the index and the affected `be_user` properties are the values. This array gets merged in order from top to bottom for each group the user is a member of.

For example:

```php
$GLOBALS['TYPO3_CONF_VARS']['EXTCONF']['azure_ad_be']['groups'] = [
	'admin-group-name' => [
		'admin' => 1
	],
	'editor-group' => [
		'usergroup' => 12
	]
];
```

### Disable TYPO3 login

If you want to disable logging in via username and password, add the following to your `ext_localconf.php`

```php
unset($GLOBALS['TYPO3_CONF_VARS']['EXTCONF']['backend']['loginProviders'][1433416747]);
```
