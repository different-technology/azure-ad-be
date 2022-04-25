# Azure Active Directory - TYPO3 Backend Login

## Setup

Add the following env parameters:
```
TYPO3_AZURE_AD_BE_CLIENT_ID=<your-client-id>
TYPO3_AZURE_AD_BE_CLIENT_SECRET=<your-secret>
TYPO3_AZURE_AD_BE_URL_AUTHORIZE=https://login.microsoftonline.com/<see-your-endpoints>/oauth2/v2.0/authorize
TYPO3_AZURE_AD_BE_URL_ACCESS_TOKEN=https://login.microsoftonline.com/<see-your-endpoints>/oauth2/v2.0/token
```
