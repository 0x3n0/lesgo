package takeover

// Fingerprints contains known service patterns for subdomain takeover detection.
// Each entry maps CNAME patterns and HTTP error fingerprints to known vulnerable services.
var Fingerprints = []ServiceFingerprint{
	// === Cloud Storage ===
	{
		Name:     "AWS S3",
		Provider: "Amazon Web Services",
		CNAMEPatterns: []string{
			"s3.amazonaws.com",
			"s3-website",
			"s3.amazonaws.com.",
			".s3.",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"The specified bucket does not exist",
					"NoSuchBucket",
					"Code: NoSuchBucket",
				},
			},
		},
	},
	{
		Name:     "Google Cloud Storage",
		Provider: "Google Cloud Platform",
		CNAMEPatterns: []string{
			"storage.googleapis.com",
			"c.storage.googleapis.com",
			"commondatastorage.googleapis.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"The specified bucket does not exist",
					"NoSuchBucket",
				},
			},
		},
	},
	{
		Name:     "Azure Storage",
		Provider: "Microsoft Azure",
		CNAMEPatterns: []string{
			"blob.core.windows.net",
			"web.core.windows.net",
			"azurewebsites.net",
			"cloudapp.net",
			"trafficmanager.net",
			"azure-api.net",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"The specified resource does not exist",
					"BlobNotFound",
				},
			},
		},
	},
	{
		Name:     "Azure CDN",
		Provider: "Microsoft Azure",
		CNAMEPatterns: []string{
			"azureedge.net",
			"vo.msecnd.net",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 400,
				BodyContains: []string{
					"The requested resource does not exist",
				},
			},
		},
	},

	// === PaaS / Hosting ===
	{
		Name:     "GitHub Pages",
		Provider: "GitHub",
		CNAMEPatterns: []string{
			"github.io",
			"githubpages.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"There isn't a GitHub Pages site here",
					"here isn't a GitHub Pages site here",
				},
			},
		},
	},
	{
		Name:     "Heroku",
		Provider: "Salesforce",
		CNAMEPatterns: []string{
			"herokuapp.com",
			"herokussl.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"No such app",
					"There's nothing here",
					"no-such-app",
				},
			},
		},
	},
	{
		Name:     "Netlify",
		Provider: "Netlify",
		CNAMEPatterns: []string{
			"netlify.app",
			"netlify.com",
			"netlifyglobalcdn.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"Not Found - Netlify",
					"Site not found",
				},
				BodyRegex: []string{
					`(?i)netlify`,
				},
			},
		},
	},
	{
		Name:     "Vercel",
		Provider: "Vercel Inc.",
		CNAMEPatterns: []string{
			"vercel.app",
			"vercel.com",
			"now.sh",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"DEPLOYMENT_NOT_FOUND",
					"404: NOT_FOUND",
				},
			},
		},
	},
	{
		Name:     "Surge.sh",
		Provider: "Surge",
		CNAMEPatterns: []string{
			"surge.sh",
			"na-west1.surge.sh",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"project not found",
					"Surge — Not Found",
				},
			},
		},
	},
	{
		Name:     "Pantheon",
		Provider: "Pantheon Systems",
		CNAMEPatterns: []string{
			"pantheonsite.io",
			"gotpantheon.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"404 - Page not found",
					"This site is not currently active",
				},
			},
		},
	},

	// === E-Commerce ===
	{
		Name:     "Shopify",
		Provider: "Shopify Inc.",
		CNAMEPatterns: []string{
			"myshopify.com",
			"shopify.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"Sorry, this shop is currently unavailable",
					"Only one step left",
				},
			},
		},
	},
	{
		Name:     "BigCommerce",
		Provider: "BigCommerce",
		CNAMEPatterns: []string{
			"bigcommerce.com",
			"mybigcommerce.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"The page you were looking for cannot be found",
				},
			},
		},
	},

	// === Marketing / Landing Pages ===
	{
		Name:     "Unbounce",
		Provider: "Unbounce",
		CNAMEPatterns: []string{
			"unbouncepages.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"The requested page was not found",
				},
			},
		},
	},
	{
		Name:     "HubSpot",
		Provider: "HubSpot",
		CNAMEPatterns: []string{
			"hs-sites.com",
			"hubspotpagebuilder.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"Domain not yet connected",
				},
			},
		},
	},

	// === CMS / Blogging ===
	{
		Name:     "WordPress.com",
		Provider: "Automattic",
		CNAMEPatterns: []string{
			"wordpress.com",
			"wpcomstaging.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"Do you want to register",
					"does not exist",
				},
			},
		},
	},
	{
		Name:     "Tumblr",
		Provider: "Automattic",
		CNAMEPatterns: []string{
			"domains.tumblr.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"Not found",
					"There's nothing here",
				},
			},
		},
	},
	{
		Name:     "Readme.io",
		Provider: "ReadMe",
		CNAMEPatterns: []string{
			"readme.io",
			"readmessl.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"Project not found",
					"The project you are looking for could not be found",
				},
			},
		},
	},
	{
		Name:     "Ghost",
		Provider: "Ghost Foundation",
		CNAMEPatterns: []string{
			"ghost.io",
			"ghost.org",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"The site you are looking for could not be found",
				},
			},
		},
	},

	// === Customer Support ===
	{
		Name:     "Zendesk",
		Provider: "Zendesk Inc.",
		CNAMEPatterns: []string{
			"zendesk.com",
			"zendesk-help.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"Help Center Closed",
					"Oops, this help center no longer exists",
					"Account does not exist",
				},
			},
		},
	},
	{
		Name:     "Help Scout",
		Provider: "Help Scout",
		CNAMEPatterns: []string{
			"helpscoutdocs.com",
			"helpscout.net",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"No such site",
					"site not found",
				},
			},
		},
	},
	{
		Name:     "Freshdesk",
		Provider: "Freshworks",
		CNAMEPatterns: []string{
			"freshdesk.com",
			"freshservice.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"You are being redirected to the Freshdesk portal",
				},
			},
		},
	},
	{
		Name:     "Intercom",
		Provider: "Intercom",
		CNAMEPatterns: []string{
			"intercom.help",
			"intercom.io",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"This page is reserved for a Intercom customer",
				},
			},
		},
	},

	// === CDN / Performance ===
	{
		Name:     "Fastly",
		Provider: "Fastly Inc.",
		CNAMEPatterns: []string{
			"fastly.net",
			"fastly-",
			"global.prod.fastly.net",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 500,
				BodyContains: []string{
					"Fastly error: unknown domain",
					"domain: unknown",
				},
			},
		},
	},
	{
		Name:     "CloudFront",
		Provider: "Amazon Web Services",
		CNAMEPatterns: []string{
			"cloudfront.net",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 403,
				BodyContains: []string{
					"Bad request",
					"ERROR: The request could not be satisfied",
				},
			},
		},
	},

	// === Others ===
	{
		Name:     "Bitbucket",
		Provider: "Atlassian",
		CNAMEPatterns: []string{
			"bitbucket.io",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"Repository not found",
					"There isn't anything here",
				},
			},
		},
	},
	{
		Name:     "LaunchRock",
		Provider: "LaunchRock",
		CNAMEPatterns: []string{
			"launchrock.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"It looks like you may have taken a wrong turn",
					"LaunchRock - page not found",
				},
			},
		},
	},
	{
		Name:     "Squarespace",
		Provider: "Squarespace",
		CNAMEPatterns: []string{
			"squarespace.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"Unconfigured Domain",
					"is not yet configured",
				},
			},
		},
	},
	{
		Name:     "Statuspage",
		Provider: "Atlassian",
		CNAMEPatterns: []string{
			"statuspage.io",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"Status page not found",
					"You are being redirected",
				},
			},
		},
	},
	{
		Name:     "Tilda",
		Provider: "Tilda Publishing",
		CNAMEPatterns: []string{
			"tildacdn.com",
			"tilda.ws",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"Domain is not bound",
				},
			},
		},
	},
	{
		Name:     "Mailgun",
		Provider: "Mailgun Technologies",
		CNAMEPatterns: []string{
			"mailgun.org",
			"mailgun.info",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"Domain not found",
				},
			},
		},
	},
	{
		Name:     "SendGrid",
		Provider: "Twilio",
		CNAMEPatterns: []string{
			"sendgrid.net",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 403,
				BodyContains: []string{
					"Access Forbidden",
				},
			},
		},
	},
	{
		Name:     "Acquia",
		Provider: "Acquia Inc.",
		CNAMEPatterns: []string{
			"acquia-test.co",
			"acquia-sites.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"Site not found",
					"This site is currently unavailable",
				},
			},
		},
	},
	{
		Name:     "Thinkific",
		Provider: "Thinkific",
		CNAMEPatterns: []string{
			"thinkific.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"This site is not currently available",
				},
			},
		},
	},
	{
		Name:     "Cargo",
		Provider: "Cargo Collective",
		CNAMEPatterns: []string{
			"cargocollective.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"404 Not Found",
				},
			},
		},
	},
	{
		Name:     "JetBrains",
		Provider: "JetBrains",
		CNAMEPatterns: []string{
			"spaces.p.jetbrains.team",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 404,
				BodyContains: []string{
					"Project not found",
				},
			},
		},
	},

	// === NS Takeover ===
	{
		Name:     "NS Takeover - AWS Route53",
		Provider: "Amazon Web Services",
		NSPatterns: []string{
			"awsdns-",
			"amazonaws.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 0,
				BodyContains: []string{
					"NXDOMAIN",
				},
			},
		},
	},
	{
		Name:     "NS Takeover - DigitalOcean",
		Provider: "DigitalOcean",
		NSPatterns: []string{
			"ns1.digitalocean.com",
			"ns2.digitalocean.com",
			"ns3.digitalocean.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 0,
				BodyContains: []string{
					"NXDOMAIN",
				},
			},
		},
	},
	{
		Name:     "NS Takeover - NS1",
		Provider: "NS1",
		NSPatterns: []string{
			"dns1.p01.nsone.net",
			"dns2.p01.nsone.net",
			"dns3.p01.nsone.net",
			"dns4.p01.nsone.net",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 0,
				BodyContains: []string{
					"NXDOMAIN",
				},
			},
		},
	},
	{
		Name:     "NS Takeover - Cloudflare",
		Provider: "Cloudflare",
		NSPatterns: []string{
			"ns.cloudflare.com",
		},
		HTTPPatterns: []FingerprintMatch{
			{
				StatusCode: 0,
				BodyContains: []string{
					"NXDOMAIN",
				},
			},
		},
	},
}
