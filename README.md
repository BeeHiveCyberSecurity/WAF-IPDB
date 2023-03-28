# Cloudflare WAF to AbuseIPDB

## What's this?

A GitHub Workflow-friendly template that when configured correctly, will auto-report firewall block events to AbuseIPDB.

## What it does?

Get IPs blocked (blocked/managed challenges) by Cloudflare WAF from Cloudflare Graphql API and submit to AbuseIPDB

## How to use for yourself

Don't fork this repo - that's not how this is designed to be used. Instead, select "Use this template", then "Create new repository".

Actions：

If you don't configure these, you'll stare at errors for eternity wondering where you're fucking up. After you create a new repository thru "Use This Template", go into the repository settings, then go to "Secrets", then add the following things with the following names. 

- `CLOUDFLARE_ZONE_ID`: Cloudflare ZONE ID
- `CLOUDFLARE_API_KEY`: Cloudflare API Key
- `CLOUDFLARE_EMAIL`: Cloudflare Email
- `ABUSEIPDB_API_KEY`: AbuseIPDB API Key


## Related

[AbuseIPDB-to-Cloudflare-WAF](https://github.com/MHG-LAB/AbuseIPDB-to-Cloudflare-WAF)

## Support

[AbuseIPDB](https://www.abuseipdb.com/) : AbuseIPDB is an IP address blacklist for webmasters and sysadmins to report IP addresses engaging in abusive behavior on their networks

[Cloudflare](https://www.cloudflare.com/)

[Cloudflare Block Bad Bot Ruleset](https://github.com/XMD0718/cloudflare-block-bad-bot-ruleset)

## AbuseIPDB Contributor

<a href="https://www.beehive.systems" title="AbuseIPDB is an IP address blacklist for webmasters and sysadmins to report IP addresses engaging in abusive behavior on their networks">
	<img src="https://www.abuseipdb.com/contributor/102055.svg" alt="AbuseIPDB Contributor Badge" style="width: 781px;border-radius: 5px;border-top: 5px solid #058403;border-right: 5px solid #111;border-bottom: 5px solid #111;border-left: 5px solid #058403;padding: 5px;background: #35c246 linear-gradient(rgba(255,255,255,0), rgba(255,255,255,.3) 50%, rgba(0,0,0,.2) 51%, rgba(0,0,0,0));padding: 5px;box-shadow: 2px 2px 1px 1px rgba(0, 0, 0, .2);">
</a>

## License

[MIT](https://github.com/MHG-LAB/Cloudflare-WAF-to-AbuseIPDB/blob/main/LICENSE)
