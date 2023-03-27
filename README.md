# Cloudflare WAF to AbuseIPDB

## 这是什么？

我也不知道

## 它可以干嘛

从 Cloudflare Graphql API 获取被 Cloudflare WAF 拦截(阻止/托管质询)的 IP 并提交给 AbuseIPDB

## 它要怎么用

请不要 fork 此仓库！！ 使用模板导入 [Use this template](https://github.com/MHG-LAB/Cloudflare-WAF-to-AbuseIPDB/generate) !! 瞎点fork按钮发送垃圾 PR 将直接提交到 GitHub 黑名单中(

Actions 环境变量：
- `CLOUDFLARE_ZONE_ID`: Cloudflare ZONE ID
- `CLOUDFLARE_API_KEY`: Cloudflare API Key
- `CLOUDFLARE_EMAIL`: Cloudflare Email
- `ABUSEIPDB_API_KEY`: AbuseIPDB API Key

## 这些奇奇怪怪的文件是什么？

有人经常访问这些，然而我这里又没有这些文件，于是我创建了他们。

例如这些：

- https://abuseipdb.mhuig.top/robots.txt
- https://abuseipdb.mhuig.top/phpinfo.php
- https://abuseipdb.mhuig.top/wp-login.php
- https://abuseipdb.mhuig.top/../../../../../../../etc/passwd
- etc.

## 吐槽

Cloudflare 的 API 不知道什么时候做了更改，找到文档时发现 PAYLOAD 需要使用 Graphql....

如果 IP 有误伤，请联系我添加白名单！

## 相关项目

[AbuseIPDB-to-Cloudflare-WAF](https://github.com/MHG-LAB/AbuseIPDB-to-Cloudflare-WAF)

或许可以构建反馈调节系统？

## Support

[AbuseIPDB](https://www.abuseipdb.com/) : AbuseIPDB is an IP address blacklist for webmasters and sysadmins to report IP addresses engaging in abusive behavior on their networks

[Cloudflare](https://www.cloudflare.com/)

[Cloudflare Block Bad Bot Ruleset](https://github.com/XMD0718/cloudflare-block-bad-bot-ruleset)

## AbuseIPDB Contributor 

<a href="https://abuseipdb.mhuig.top/" title="AbuseIPDB is an IP address blacklist for webmasters and sysadmins to report IP addresses engaging in abusive behavior on their networks">
	<img src="https://www.abuseipdb.com/contributor/82131.svg" alt="AbuseIPDB Contributor Badge" style="width: 781px;border-radius: 5px;border-top: 5px solid #058403;border-right: 5px solid #111;border-bottom: 5px solid #111;border-left: 5px solid #058403;padding: 5px;background: #35c246 linear-gradient(rgba(255,255,255,0), rgba(255,255,255,.3) 50%, rgba(0,0,0,.2) 51%, rgba(0,0,0,0));padding: 5px;box-shadow: 2px 2px 1px 1px rgba(0, 0, 0, .2);">
</a>

## License

[MIT](https://github.com/MHG-LAB/Cloudflare-WAF-to-AbuseIPDB/blob/main/LICENSE)