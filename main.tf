terraform {
  required_providers {
    sigsci = {
      source = "signalsciences/sigsci"
	  version = "1.0.1"
    }
  }
}

variable "SIGSCI_CORP" {
    type        = string
    description = "This is the corp where configuration changes will be made as an env variable."
}
variable "SIGSCI_EMAIL" {
    type        = string
    description = "This is the email address associated with the token for the Sig Sci API as an env variable."
}
variable "SIGSCI_TOKEN" {
    type        = string
    description = "This is a secret token for the Sig Sci API as an env variable."
}
variable "SIGSCI_SITE" {
    type        = string
    description = "This is the site for the Sig Sci API as an env variable."
}
variable "ROBOTS_DISALLOW_LIST" {
    type        = list
    description = "List of paths that are disallowed in robots.txt. https://developers.google.com/search/docs/advanced/robots/intro"
}

# Supply API authentication
provider "sigsci" {
  corp = "${var.SIGSCI_CORP}"
  email = "${var.SIGSCI_EMAIL}"
  auth_token = "${var.SIGSCI_TOKEN}"
}

#### start attack from suspicious sources
# Add a tag for attacks from known suspicious sources
resource "sigsci_corp_signal_tag" "attack-sus-src" {
  short_name  = "attack-sus-src"
  description = "Attacks from suspicious sources"
}

##Cut



#### start card-input discovery
# Signal for discovering when credit cards or gift cards are used.
resource "sigsci_corp_signal_tag" "sus-card-input" {
  short_name      = "sus-card-input"
  description     = "Make sure these requests are visibible in your carding dashboard or customize the rule to avoid adding this Signal to rules"
}

# Add a signal when there is a suspected login
resource "sigsci_corp_rule" "sus-card-input-rule" {
    corp_scope       = "global"
    enabled          = true
    group_operator   = "all"
    reason           = "Add signal for suspected carding attempt"
    site_short_names = []
    type             = "request"
    expiration = ""
    actions {
        signal = "corp.sus-card-input"
        type   = "addSignal"
    }
    conditions {
        group_operator = "any"
        type           = "group"

        conditions {
            field          = "postParameter"
            group_operator = "any"
            operator       = "exists"
            type           = "multival"

            conditions {
                field    = "name"
                operator = "contains"
                type     = "single"
                value    = "creditcard"
            }
            conditions {
                field    = "name"
                operator = "contains"
                type     = "single"
                value    = "credit-card"
            }
            conditions {
                field    = "name"
                operator = "contains"
                type     = "single"
                value    = "cvv"
            }
        }
        conditions {
            field    = "path"
            operator = "contains"
            type     = "single"
            value    = "/creditcard"
        }
        conditions {
            field    = "path"
            operator = "contains"
            type     = "single"
            value    = "/credit-card"
        }
    }
    conditions {
        field    = "method"
        operator = "equals"
        type     = "single"
        value    = "POST"
    }
	depends_on = [
	sigsci_corp_signal_tag.sus-card-input
  ]
}
#### end card-input discovery


#### start robots.txt

# create list to disallow based on robots.txt
# run the script get-robots-txt.sh first to generate the terraform variable file in main.auto.tfvars
resource "sigsci_corp_list" "robots-txt-disallow-list" {
  name        = "robots-txt disallow list"
  type        = "wildcard"
  description = "list of wildcard paths disallowed from robots.txt"
  entries = "${var.ROBOTS_DISALLOW_LIST}"
}

# Signal for discovering when bots are submitting requests to disallowed robots.txt resources
resource "sigsci_corp_signal_tag" "robots-txt-disallow" {
  short_name      = "robots-txt-disallow"
  description     = "Requests made by bots to disallowed pages defined in robots.txt"
}

# create rule to disallow based on robots.txt
resource "sigsci_corp_rule" "robots-txt-disallow-rule" {
corp_scope       = "global"
    enabled          = true
    group_operator   = "all"
    reason           = "Requests made by bots to disallowed paths in robots.txt"
    site_short_names = []
    type             = "request"
    expiration       = ""

    actions {
        signal = "corp.robots-txt-disallow"
        type   = "addSignal"
    }

    conditions {
        field          = "signal"
        group_operator = "any"
        operator       = "exists"
        type           = "multival"

        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "SUSPECTED-BAD-BOT"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "SUSPECTED-BOT"
        }
    }
    conditions {
        field    = "path"
        operator = "inList"
        type     = "single"
        value    = "corp.robots-txt-disallow-list"
    }
	depends_on = [
	sigsci_corp_signal_tag.robots-txt-disallow
  ]
}
#### end robots.txt

resource "sigsci_corp_signal_tag" "ofac" {
  short_name  = "ofac"
  description = "Countries on OFAC list"
}

resource "sigsci_corp_list" "ofac" {
    name = "Blocked Countries"
    type = "country"
    entries = [
        "RU",
        "SY",
        "SD",
        "KP",
        "BY",
        "CI",
        "CU",
        "CD",
        "IQ",
        "LR",
        "MM",
        "ZW",
    ]
}

resource "sigsci_corp_rule" "ofac" {
  site_short_names = []
  type = "request"
  corp_scope = "global"
  enabled = true
  group_operator = "all"
  reason = "Country Blocking Rule"
  expiration = ""

  conditions {
    type     = "single"
    field    = "country"
    operator = "inList"
    value = "corp.ofac-countries"
  }

  actions {
    type = "block"
  }

  actions {
    type = "addSignal"
    signal = "corp.ofac" 
  }
}

resource "sigsci_corp_signal_tag" "domain-signal" {
  short_name  = "domain-request"
  description = "Tagging requests to the domain"
}

resource "sigsci_corp_list" "domain-list" {
    name = "Domain List"
    type = "wildcard"
    entries = [ // Change values in this list to reflect your domain
        "owasp.fastlylab.com",
	"www.fastlylab.com",
	"*.fastlylab.com",
	"overseerr.mediakumo.com",
	"plex.mediakumo.com",
	"*.mediakumo.com",
    ]
}

resource "sigsci_corp_rule" "domain-rule" {
  site_short_names = []
  type = "request"
  corp_scope = "global"
  enabled = true
  group_operator = "all"
  reason = "Identify requests with valid domain in host header"
  expiration = ""

  conditions {
    type     = "single"
    field    = "domain"
    operator = "inList"
    value = "corp.domain-list"
  }

  actions {
    type   = "addSignal"
    signal = "corp.domain-request" 
  }
  depends_on = [
  sigsci_corp_list.domain-list
  ]	

}
