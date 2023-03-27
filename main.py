import json
import requests
import time
import os
import yaml
import sys

def load_config(path):
  f = open(path, 'r', encoding='utf-8')
  ystr = f.read()
  ymllist = yaml.load(ystr, Loader=yaml.FullLoader)
  return ymllist

if os.path.exists('config.yml'):
  c=load_config('config.yml')
  CLOUDFLARE_ZONE_ID = c['CLOUDFLARE_ZONE_ID']
  CLOUDFLARE_EMAIL = c['CLOUDFLARE_EMAIL']
  CLOUDFLARE_API_KEY = c['CLOUDFLARE_API_KEY']
  ABUSEIPDB_API_KEY = c['ABUSEIPDB_API_KEY']
else:
  CLOUDFLARE_ZONE_ID = sys.argv[1]
  CLOUDFLARE_EMAIL = sys.argv[2]
  CLOUDFLARE_API_KEY = sys.argv[3]
  ABUSEIPDB_API_KEY = sys.argv[4]

PAYLOAD={
  "query": """query ListFirewallEvents($zoneTag: string, $filter: FirewallEventsAdaptiveFilter_InputObject) {
    viewer {
      zones(filter: { zoneTag: $zoneTag }) {
        firewallEventsAdaptive(
          filter: $filter
          limit: 1000
          orderBy: [datetime_DESC]
        ) {
          action
          clientASNDescription
          clientAsn
          clientCountryName
          clientIP
          clientRequestHTTPHost
          clientRequestHTTPMethodName
          clientRequestHTTPProtocol
          clientRequestPath
          clientRequestQuery
          datetime
          rayName
          ruleId
          source
          userAgent
        }
      }
    }
  }""",
  "variables": {
    "zoneTag": CLOUDFLARE_ZONE_ID,
    "filter": {
      "datetime_geq": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.localtime(time.time()-60*60*8-60*60*2.5)),
      "datetime_leq": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.localtime(time.time()-60*60*8)),
      # "OR":[{"action": "block"}, {"action": "managed_challenge"}, {"action": "jschallenge"}],
      "AND":[
          {"action_neq": "allow"},
          {"action_neq": "challenge_solved"},
          {"action_neq": "challenge_failed"},
          {"action_neq": "challenge_bypassed"},
          {"action_neq": "jschallenge_solved"},
          {"action_neq": "jschallenge_failed"},
          {"action_neq": "jschallenge_bypassed"},
          {"action_neq": "managed_challenge_skipped"},
          {"action_neq": "managed_challenge_non_interactive_solved"},
          {"action_neq": "managed_challenge_interactive_solved"},
          {"action_neq": "managed_challenge_bypassed"},
      ]
    }
  }
}
PAYLOAD = json.dumps(PAYLOAD)
headers={"Content-Type":"application/json","X-Auth-Key":CLOUDFLARE_API_KEY,"X-Auth-Email":CLOUDFLARE_EMAIL}

ttl=60
def get_blocked_ip():
  global ttl
  ttl=ttl-1
  print("ttl:",ttl)
  if ttl<=0:
    return []
  try:
    r=requests.post("https://api.cloudflare.com/client/v4/graphql/",headers=headers,data=PAYLOAD)
    if str(type(r.json())) == "<class 'NoneType'>":
      get_blocked_ip()
    else:
      return r.json()
  except Exception as e:
    get_blocked_ip()

def get_comment(it):
  return "Threat Blocked by BeeHive from ASN: "+it['clientAsn']+" Network: "+it['clientASNDescription']+" Host: "+it['clientRequestHTTPHost']+" Method: "+it['clientRequestHTTPMethodName']+" Protocol: "+it['clientRequestHTTPProtocol']+" datetime: "+it['datetime']+" userAgent: "+it['userAgent']+"."

def report_bad_ip(it):
  try:
    url = 'https://api.abuseipdb.com/api/v2/report'
    params = {
      'ip': it['clientIP'],
      'categories': '9,13,14,15,16,19,20,21',
      'comment': get_comment(it)
    }
    headers = {
      'Accept': 'application/json',
      'Key': ABUSEIPDB_API_KEY
    }
    r=requests.post(url=url, headers=headers, params=params)
    if r.status_code==200:
      print("reported:",it['clientIP'])
    else:
      print("error:",r.status_code)
    decodedResponse = json.loads(r.text)
    print(json.dumps(decodedResponse, sort_keys=True, indent=4))
  except Exception as e:
    print("error:",e)

# 排除配置错误的规则
excepted_ruleId = ["fa01280809254f82978e827892db4e46"]

print("==================== Start ====================")
print(str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))
print(str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()-60*60*8))))
a=get_blocked_ip()
print(str(type(a)))
if str(type(a)) == "<class 'dict'>" and len(a)>0:
  ip_bad_list=a["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
  print(len(ip_bad_list))
  # print(a["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"][0])
  # {'action': 'managed_challenge', 'clientASNDescription': 'BABBAR-AS', 'clientAsn': '210743', 'clientCountryName': 'FR', 'clientIP': '154.54.249.200', 'clientRequestHTTPHost': 'blog.mhuig.top', 'clientRequestHTTPMethodName': 'GET', 'clientRequestHTTPProtocol': 'HTTP/1.1', 'clientRequestPath': '/robots.txt', 'clientRequestQuery': '', 'datetime': '2022-04-20T13:06:49Z', 'rayName': '6fee19707fd03afb', 'ruleId': '8ef3496625dc456b899f3497ccedcd50', 'source': 'firewallrules', 'userAgent':'Mozilla/5.0 (compatible; Barkrowler/0.9; +https://babbar.tech/crawler)'}

  reported_ip_list=[]
  for i in ip_bad_list:
    if i['ruleId'] not in excepted_ruleId:
      if i['clientIP'] not in reported_ip_list:
        report_bad_ip(i)
        reported_ip_list.append(i['clientIP'])

  print(len(reported_ip_list))
print("==================== End ====================")
