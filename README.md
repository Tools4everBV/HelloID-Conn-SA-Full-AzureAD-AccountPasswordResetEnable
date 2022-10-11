
<!-- Description -->
## Description
This HelloID Service Automation Delegated Form can reset the password of and/or enable Azure users. The following options are available:
 1. Search and select the target user
 2. Optional, Select the switch for Reset Password
  2. 1. Enter the new password
  2. 2. Optional, Select the switch for Change password at next sign in
 3. Optional, Select the switch for Enable account
 3. After confirmation the password is reset and optionally, the user is enabled

## Versioning
| Version | Description | Date |
| - | - | - |
| 1.0.2   | Updated to use id instead of upn to get correct user | 2022/10/11  |
| 1.0.2   | Added version number and updated code for SA-agent and auditlogging | 2022/08/16  |
| 1.0.1   | Added version number and updated all-in-one script | 2021/11/08  |
| 1.0.0   | Initial release | 2021/09/02  |

<!-- Requirements -->
## Requirements
This script uses the Microsoft Graph API and requires an App Registration with App permissions:
*	Read and Write all user’s full profiles by using *__User.ReadWrite.All__*
*	Read and Write all groups in an organization’s directory by using *__Group.ReadWrite.All__*
*	Read and Write data to an organization’s directory by using *__Directory.ReadWrite.All__*

Apart from the App Permissions, to reset a password one fo the following roles (from least to most privileged) is requires as well:
*	*__Helpdesk (Password) administrator__*
*	*__User Administrator__*
*	*__Global Administrator__*

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [Description](#description)
- [Versioning](#versioning)
- [Requirements](#requirements)
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Getting the Azure AD graph API access](#getting-the-azure-ad-graph-api-access)
  - [Application Registration](#application-registration)
  - [Configuring App Permissions](#configuring-app-permissions)
  - [Authentication and Authorization](#authentication-and-authorization)
  - [Password Reset Permissions](#password-reset-permissions)
- [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
  - [Getting started](#getting-started)
- [Post-setup configuration](#post-setup-configuration)
- [Manual resources](#manual-resources)
  - [Powershell data source 'Azure-AD-User-Reset-Password-generate-table-attributes-basic'](#powershell-data-source-azure-ad-user-reset-password-generate-table-attributes-basic)
  - [Powershell data source 'Azure-AD-User-Reset-Password-generate-table-wildcard'](#powershell-data-source-azure-ad-user-reset-password-generate-table-wildcard)
  - [Delegated form task 'Azure AD Account - Reset password & Unlock'](#delegated-form-task-azure-ad-account---reset-password--unlock)
- [Getting help](#getting-help)
- [HelloID Docs](#helloid-docs)


## Introduction
The interface to communicate with Microsoft Azure AD is through the Microsoft Graph API.

<!-- GETTING STARTED -->
## Getting the Azure AD graph API access

By using this connector you will have the ability to reset the password of and/or enable an Azure AD User.

### Application Registration
The first step to connect to Graph API and make requests, is to register a new __Azure Active Directory Application__. The application is used to connect to the API and to manage permissions.

* Navigate to __App Registrations__ in Azure, and select “New Registration” (__Azure Portal > Azure Active Directory > App Registration > New Application Registration__).
* Next, give the application a name. In this example we are using “__HelloID PowerShell__” as application name.
* Specify who can use this application (__Accounts in this organizational directory only__).
* Specify the Redirect URI. You can enter any url as a redirect URI value. In this example we used http://localhost because it doesn't have to resolve.
* Click the “__Register__” button to finally create your new application.

Some key items regarding the application are the Application ID (which is the Client ID), the Directory ID (which is the Tenant ID) and Client Secret.

### Configuring App Permissions
The [Microsoft Graph documentation](https://docs.microsoft.com/en-us/graph) provides details on which permission are required for each permission type.

To assign your application the right permissions, navigate to __Azure Portal > Azure Active Directory >App Registrations__.
Select the application we created before, and select “__API Permissions__” or “__View API Permissions__”.
To assign a new permission to your application, click the “__Add a permission__” button.
From the “__Request API Permissions__” screen click “__Microsoft Graph__”.
For this connector the following permissions are used as __Application permissions__:
*	Read and Write all user’s full profiles by using *__User.ReadWrite.All__*
*	Read and Write all groups in an organization’s directory by using *__Group.ReadWrite.All__*
*	Read and Write data to an organization’s directory by using *__Directory.ReadWrite.All__*

Some high-privilege permissions can be set to admin-restricted and require an administrators consent to be granted.

To grant admin consent to our application press the “__Grant admin consent for TENANT__” button.

### Authentication and Authorization
There are multiple ways to authenticate to the Graph API with each has its own pros and cons, in this example we are using the Authorization Code grant type.

*	First we need to get the __Client ID__, go to the __Azure Portal > Azure Active Directory > App Registrations__.
*	Select your application and copy the Application (client) ID value.
*	After we have the Client ID we also have to create a __Client Secret__.
*	From the Azure Portal, go to __Azure Active Directory > App Registrations__.
*	Select the application we have created before, and select "__Certificates and Secrets__". 
*	Under “Client Secrets” click on the “__New Client Secret__” button to create a new secret.
*	Provide a logical name for your secret in the Description field, and select the expiration date for your secret.
*	It's IMPORTANT to copy the newly generated client secret, because you cannot see the value anymore after you close the page.
*	At least we need to get is the __Tenant ID__. This can be found in the Azure Portal by going to __Azure Active Directory > Custom Domain Names__, and then finding the .onmicrosoft.com domain.

### Password Reset Permissions
Additionally you might need to add the User administrator role

*	From the Azure Portal, Under Manage, select Roles and administrators.
*	Select the application we have created before, and select "__Certificates and Secrets__". 
*	Search and select the User administrator role.
*	Select Add assignments.
*	In the Select text box, enter the name or the ID of the application you registered earlier. When it appears in the search results, select your application.
*	Select Add. It might take a few minutes to for the permissions to fully propagate

## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user defined variables, tasks and data sources.

_Please note that this script asumes none of the required resources do exists within HelloID. The script does not contain versioning or source control_

### Getting started
Please follow the documentation steps on [HelloID Docs](https://docs.helloid.com/hc/en-us/articles/360017556559-Service-automation-GitHub-resources) in order to setup and run the All-in one Powershell Script in your own environment.


## Post-setup configuration
After the all-in-one PowerShell script has run and created all the required resources. The following items need to be configured according to your own environment
 1. Update the following [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables)
<table>
  <tr><td><strong>Variable name</strong></td><td><strong>Example value</strong></td><td><strong>Description</strong></td></tr>
  <tr><td>AADtenantID</td><td>Azure AD Tenant Id</td><td>Id of the Azure tenant</td></tr>
  <tr><td>AADAppId</td><td>Azure AD App Id</td><td>Id of the Azure app</td></tr>
<tr><td>AADAppSecret</td><td>Azure AD App Secret</td><td>Secreat of the Azure app</td></tr>
</table>

## Manual resources
This Delegated Form uses the following resources in order to run

### Powershell data source 'Azure-AD-User-Reset-Password-generate-table-attributes-basic'

### Powershell data source 'Azure-AD-User-Reset-Password-generate-table-wildcard'

### Delegated form task 'Azure AD Account - Reset password & Unlock'

## Getting help
_If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/service-automation/194-helloid-sa-azure-ad-reset-password-enable-user)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/