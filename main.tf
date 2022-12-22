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

##Cut for Demo


resource "sigsci_corp_signal_tag" "bad-ua" {
  short_name  = "bad-ua"
  description = "Known bad User Agents block"
}

resource "sigsci_corp_list" "bad-ua" {
    name = "Bad UA"
    type = "wildcard"
    entries = [
        "*[Cc][Uu][Rr][Ll]*",
        "*[Pp][Yy][Tt][Hh][Oo][Nn]*",
        "*[Ww][Pp][Ss][Cc][Aa][Nn]*",
        "*[Nn][Mm][Aa][Pp]*",
        "*[Mm][Aa][Ss][Ss][Cc][Aa][Nn]*",
    ]
}

resource "sigsci_corp_rule" "bad-ua" {
    site_short_names = []
    type = "request"
    corp_scope = "global"
    enabled = true
    group_operator = "all"
    reason = "Bad User Agents Blocking Rule"
    expiration = ""

    conditions {
      type     = "single"
      field    = "useragent"
      operator = "inList"
      value = "corp.bad-ua"
    }

    actions {
    type = "block"
    }

    actions {
    type = "addSignal"
    signal = "corp.bad-ua" 
  }
  depends_on = [
  sigsci_corp_signal_tag.bad-ua
  ]
}

#### End  cut

#### start attack from suspicious sources
# Add a tag for attacks from known suspicious sources
resource "sigsci_corp_signal_tag" "attack-sus-src" {
  short_name  = "attack-sus-src"
  description = "Attacks from suspicious sources"
}

resource "sigsci_corp_rule" "attack-sus-src-rule" {
    corp_scope       = "global"
    enabled          = true
    group_operator   = "all"
    reason           = "Attacks from suspicious sources"
    site_short_names = []
    type             = "request"
    expiration       = ""

    actions {
        type = "block"
    }
    actions {
        signal = "corp.attack-sus-src"
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
            value    = "BACKDOOR"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "CMDEXE"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "SQLI"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "TRAVERSAL"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "USERAGENT"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "XSS"
        }
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
            value    = "SANS"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "SIGSCI-IP"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "TORNODE"
        }
    }
}
#### end attack from suspicious sources

### API Misuse example. Make API Readonly and Add signal for misuse attemps.
resource "sigsci_corp_signal_tag" "readonly-api" {
  short_name  = "readonly-api"
  description = "Signal for attempted API misuse"
}


# Add a signal when there is an API misused
resource "sigsci_corp_rule" "api-misuse" {
    corp_scope       = "global"
    enabled          = true
    group_operator   = "all"
    reason           = "Add rule to make API endpoint readonly"
    type             = "request"
    expiration = ""
    actions {
    type = "block"
    }
    actions {
    type = "addSignal"
    signal = "corp.readonly-api" 
    }
    conditions {
        group_operator = "any"
        type           = "group"

        conditions {
        field    = "method"
        operator = "equals"
        type     = "single"
        value    = "POST"
    	}
        conditions {
        field    = "path"
        operator = "contains"
        type     = "single"
        value    = "/v2/api/inventory"
        }
    }

}
### End API Misuse Section

#### start any-attack

resource "sigsci_corp_signal_tag" "any-attack-signal" {
  short_name      = "any-attack-signal"
  description     = "Flag on attack signals"
}


resource "sigsci_corp_rule" "any-attack-signal-rule" {
    corp_scope       = "global"
    enabled          = true
    group_operator   = "all"
    reason           = "Any attack signal"
    site_short_names = []
    type             = "request"
    expiration       = ""

    actions {
        signal = "corp.any-attack-signal"
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
            value    = "BACKDOOR"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "CMDEXE"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "SQLI"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "TRAVERSAL"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "USERAGENT"
        }
        conditions {
            field    = "signalType"
            operator = "equals"
            type     = "single"
            value    = "XSS"
        }
    }
}
### end any-attack


#### start login discovery
# Signal for suspected login attempts
resource "sigsci_corp_signal_tag" "sus-login" {
  short_name      = "sus-login"
  description     = "Make sure these requests are visible in your ATO dashboard or customize the rule to avoid adding this Signal to rules."
}

# Add a signal when there is a suspected login
resource "sigsci_corp_rule" "sus-login-rule" {
    corp_scope       = "global"
    enabled          = true
    group_operator   = "all"
    reason           = "Add signal for suspected logins"
    site_short_names = []
    type             = "request"
    expiration = ""
    actions {
        signal = "corp.sus-login"
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
                value    = "email"
            }
            conditions {
                field    = "name"
                operator = "equals"
                type     = "single"
                value    = "/pass"
            }
            conditions {
                field    = "name"
                operator = "contains"
                type     = "single"
                value    = "passwd"
            }
            conditions {
                field    = "name"
                operator = "contains"
                type     = "single"
                value    = "password"
            }
            conditions {
                field    = "name"
                operator = "contains"
                type     = "single"
                value    = "phone"
            }
            conditions {
                field    = "name"
                operator = "equals"
                type     = "single"
                value    = "/user"
            }
            conditions {
                field    = "name"
                operator = "contains"
                type     = "single"
                value    = "username"
            }
        }
        conditions {
            field    = "path"
            operator = "contains"
            type     = "single"
            value    = "/auth"
        }
        conditions {
            field    = "path"
            operator = "contains"
            type     = "single"
            value    = "/login"
        }
    }
    conditions {
        field    = "method"
        operator = "equals"
        type     = "single"
        value    = "POST"
    }
  depends_on = [
  sigsci_corp_signal_tag.sus-login
  ]
}
#### end login discovery


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

#### Start OFAC country rule 

resource "sigsci_corp_signal_tag" "ofac" {
  short_name  = "ofac"
  description = "Countries on OFAC list"
}

resource "sigsci_corp_list" "ofac-countries" {
    name = "OFAC Countries"
    type = "country"
    entries = [
        "IR",
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
  reason = "OFAC Country Blocking Rule"
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


#### End OFAC Country Rule ####



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

#### start site alerts
resource "sigsci_site_alert" "any-attack-1-min" {
    action             = "flagged"
    enabled            = true
    interval           = 1
    long_name          = "Any attack - 1 min"
    site_short_name    = "homelab-websites"
    skip_notifications = false
    tag_name           = "corp.any-attack-signal"
    threshold          = 10
}

resource "sigsci_site_alert" "abnormal-traffic" {
    action             = "flagged"
    enabled            = true
    interval           = 1
    long_name          = "Abnormal Traffic"
    site_short_name    = "personal-apps"
    skip_notifications = false
    tag_name           = "corp.abnormal-traffic"
    threshold          = 10
}

#### end site alerts
