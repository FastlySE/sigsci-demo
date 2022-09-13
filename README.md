Merging of the "Unofficial better practices for the Fastly Next Gen WAF" and other Terraform examples into one terraform plan.

The Fastly Next Gen WAF (Signal Sciences) is amazing right out of the box. We can use the framework that it provides to provide more suggestions about how to get the most out of the product. This repository provides the following functionaliy.

Block attack traffic from known suspicious sources
Consolidate the various malicious attack traffic into a single signal
Discover login endpoints
Discover card endpoints
Block bots based on disallow in robots.txt
Add a Rule to block requests with invalid Host headers
Country blocking rule


We will need to authenticate and provide the shortname for the Corp. In order to authenticate you need the e-mail address of the account used to authenticate to the Signal Sciences Dashboard and an API token for the account.

To authenticate, set the environment variables for e-mail and API token:

export SIGSCI_EMAIL="[your-email]"

export SIGSCI_TOKEN="[your-api-token]"

Next, set the environment variable for the Corp name:

export SIGSCI_CORP="[your-corp-shortname]"
