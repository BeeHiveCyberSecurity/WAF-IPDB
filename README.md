# Cloudflare WAF to AbuseIPDB

## Summary

This is a Python script that queries Cloudflare's firewall event logs and reports any potentially malicious IP addresses to AbuseIPDB, a database that tracks IPs associated with malicious activities.

The script first imports several libraries: `json`, `requests`, `time`, `os`, `yaml`, and `sys`.

- `json` is used for encoding and decoding JSON data, which is used by the Cloudflare and AbuseIPDB APIs.
- `requests` is used to make HTTP requests to the Cloudflare and AbuseIPDB APIs.
- `time` is used to get the current time and format it for use in the query payload.
- `os` and `sys` are used to load configuration data from a YAML file or environment variables.

The `load_config` function reads a YAML file and returns a dictionary of the file's contents.

If a `config.yml` file exists in the current directory, the script loads configuration data from it. If the file does not exist, the script instead loads the configuration data from the following four environment variables: `CLOUDFLARE_ZONE_ID`, `CLOUDFLARE_EMAIL`, `CLOUDFLARE_API_KEY`, and `ABUSEIPDB_API_KEY`.

The script then constructs a payload containing a GraphQL query that filters Cloudflare's firewall event logs for potentially malicious events that occurred within the last 2.5 hours. The payload includes Cloudflare's `CLOUDFLARE_ZONE_ID` for authentication. The payload is sent as a `JSON` string to the Cloudflare API.

The script defines a function `get_blocked_ip` that sends the payload to the Cloudflare API and returns a list of potentially malicious IP addresses. The function retries the API call up to 60 times before giving up.

The script defines a function `get_comment` that takes a dictionary containing information about a potentially malicious IP address and returns a string that describes the IP address and associated details for reporting to AbuseIPDB.

The script defines a function `report_bad_ip` that takes a dictionary containing information about a potentially malicious IP address, constructs a payload containing the IP address and associated details, and sends the payload to the AbuseIPDB API to report the IP address as potentially malicious.

The script prints a message indicating that it has started and the time range of the events it considers. It then calls the `get_blocked_ip` function to retrieve a list of potentially malicious IP addresses from Cloudflare's firewall event logs. If the function returns a non-empty list, the script calls the `report_bad_ip` function for each IP address in the list, excluding any IP addresses associated with a specific rule ID. The script prints a message indicating the number of potentially malicious IP addresses found in the event logs.

## How to use for yourself

Don't fork this repo - that's not how this is designed to be used. Instead, select "Use this template", then "Create new repository".

# First, Enable and Configure GitHub Actions：

>[!TIP]
>If you don't configure these, you'll stare at errors for eternity wondering where you're going wrong.
After you create a new repository through "Use This Template", go into the repository settings, then go to "Secrets and variables" -> "Actions", then add the following repository secrets with the following names and the corresponding values:

- `CLOUDFLARE_ZONE_ID`: Cloudflare ZONE ID
- `CLOUDFLARE_API_KEY`: Cloudflare API Key
- `CLOUDFLARE_EMAIL`: Cloudflare Email
- `ABUSEIPDB_API_KEY`: AbuseIPDB API Key

After this, modify the name of your `report.yml` workflow to make the repository name match YOUR repository name. 

>[!TIP]
>Before you enable this for the first time and allow it to start reporting, REVIEW YOUR WAF SETTINGS. This worker will report your firewall events overall, so if you have a configuration that causes requests to generate logs for no reason, OR a specific security setting that issues Managed Challenges regardless of condition, then you'll equally start reporting random IPs for no reason. If you do this, your AbuseIPDB key will be revoked, and your account could be locked and/or terminated. 

## Related

[AbuseIPDB-to-Cloudflare-WAF](https://github.com/MHG-LAB/AbuseIPDB-to-Cloudflare-WAF)

## Support

[AbuseIPDB](https://www.abuseipdb.com/): AbuseIPDB is an IP address blacklist for webmasters and sysadmins to report IP addresses engaging in abusive behavior on their networks

[Cloudflare](https://www.cloudflare.com/)

[Cloudflare Block Bad Bot Ruleset](https://github.com/XMD0718/cloudflare-block-bad-bot-ruleset)

## AbuseIPDB Contributor

<a href="https://www.beehive.systems" title="AbuseIPDB is an IP address blacklist for webmasters and sysadmins to report IP addresses engaging in abusive behavior on their networks">
	<img src="https://www.abuseipdb.com/contributor/102055.svg" alt="AbuseIPDB Contributor Badge" style="width: 781px;border-radius: 5px;border-top: 5px solid #058403;border-right: 5px solid #111;border-bottom: 5px solid #111;border-left: 5px solid #058403;padding: 5px;background: #35c246 linear-gradient(rgba(255,255,255,0), rgba(255,255,255,.3) 50%, rgba(0,0,0,.2) 51%, rgba(0,0,0,0));padding: 5px;box-shadow: 2px 2px 1px 1px rgba(0, 0, 0, .2);">
</a>

This number is tied to the code in this very repo.

If this number is going up, ours is working, even if yours doesn't seem to be.

Consider yourself an... unsmooth operator.

## License

[MIT](https://github.com/MHG-LAB/Cloudflare-WAF-to-AbuseIPDB/blob/main/LICENSE)
