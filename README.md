# code-challenge

---
description: This application will assess a pre-determined data set for security issues and generate a report. It is built using ASP.NET Core Razor Pages. At this time there isn't any input validation, and lightweight error handling. Once deployed, when you browse to the web site, you will be greeted with a blank input form. Put in the sample code provided below and hit submit.

---

##


```  
{
  "resources": [
    {
      "type": "virtual_machine",
      "name": "vm1",
      "open_ports": [22, 80, 443],
      "password": "weakpassword",
      "encryption": false,
      "mfa_enabled": false,
      "azure_specific": {
        "resource_group": "rg1",
        "location": "eastus",
        "vm_size": "Standard_DS1_v2"
      }
    },
    {
      "type": "storage_account",
      "name": "storage1",
      "encryption": false,
      "azure_specific": {
        "resource_group": "rg1",
        "location": "eastus",
        "account_tier": "Standard",
        "replication": "LRS"
      }
    },
    {
      "type": "database",
      "name": "db1",
      "open_ports": [],
      "password": "supersecurepassword",
      "encryption": true,
      "mfa_enabled": true,
      "azure_specific": {
        "resource_group": "rg2",
        "location": "westus",
        "db_service": "Azure SQL Database"
      }
    },
    {
      "type": "virtual_machine",
      "name": "vm2",
      "open_ports": [22, 8080],
      "password": "anotherweakpassword",
      "encryption": false,
      "mfa_enabled": false,
      "azure_specific": {
        "resource_group": "rg2",
        "location": "westus",
        "vm_size": "Standard_B2s"
      }
    },
    {
      "type": "storage_account",
      "name": "storage2",
      "encryption": true,
      "azure_specific": {
        "resource_group": "rg3",
        "location": "centralus",
        "account_tier": "Premium",
        "replication": "GRS"
      }
    }
  ]
}

```


## How to setup

### #1 Open project from GitHub repo in Visual Studio
Follow guidance provided here: https://learn.microsoft.com/en-us/visualstudio/get-started/tutorial-open-project-from-repo?view=vs-2022

Once imported, simply build. 

### #2 Access already deployed instance of the project
Project is deployed to an Azure Web App and is accessible here: https://aspnetmrajess-dgcmhtexbve6gxec.westus2-01.azurewebsites.net/

### #3 Create your own App Service using Azure CLI
1. Log in to Azure CLI: Open your terminal and log in to Azure using the following command:

        az login
               
    This command will open a browser window for you to complete the login process.

2. Create a Resource Group: Create a new resource group where your web app and other resources will be stored. Replace \<ResourceGroupName> and \<Location> with your desired resource group name and Azure region, respectively:

        az group create --name <ResourceGroupName> --location <Location>

3. Create an App Service Plan: Create an App Service plan, which defines the region, number of instances, and pricing tier for your web app. Replace \<AppServicePlanName> and \<ResourceGroupName> with your desired app service plan name and resource group name, respectively:

        az appservice plan create --name <AppServicePlanName> --resource-group <ResourceGroupName> --sku S1

4. Create a Web App: Create the web app within the resource group and app service plan you created earlier. Replace \<WebAppName>, \<ResourceGroupName>, and \<AppServicePlanName> with your desired web app name, resource group name, and app service plan name, respectively:

        az webapp create --name <WebAppName> --resource-group <ResourceGroupName> --plan <AppServicePlanName>

5. Deploy Your Web App: You can deploy your web app using various methods such as GitHub Actions, Visual Studio, or Azure CLI. Here, we'll use the Azure CLI to deploy. Replace \<WebAppName> and \<ResourceGroupName> with your web app name and resource group name, respectively:

        az webapp deploy --resource-group <ResourceGroupName> --name <WebAppName> --src-url 'https://github.com/mrajess/code-challenge/blob/main/SecurityAssessor.zip' --type zip

6. Verify Your Web App: Once the deployment is complete, you can verify that your web app is running by navigating to the URL provided by Azure CLI. The URL will be in the format https://\<app-name>-\<random-hash>.\<region>.azurewebsites.net.