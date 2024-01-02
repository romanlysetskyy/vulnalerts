import wget
import os
import requests
import json

def get_nvd_feed():
    url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip'
    wget.download(url)
    command = 'unzip -o nvdcve-1.1-recent.json.zip'
    os.system(command)

def get_cpes():
    with open('cpe.txt', 'r') as v:
        cpe = v.readlines()
        return cpe

def parse_nvd_feed(cpes):
    get_nvd_feed()
    with open('nvdcve-1.1-recent.json', 'r') as f:
        cve_feed = json.load(f)
    cve_count = 0
    message = []

    for item in cve_feed['CVE_Items']:
        id = item['cve']['CVE_data_meta']['ID']
        description = item['cve']['description']['description_data'][0]['value']
        cve_url = item['cve']['references']['reference_data'][0]['url'] if item['cve']['references']['reference_data'] else ""
        try:
            severity = item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
        except KeyError:
            severity = "Unknown"  # If 'baseMetricV3' is missing

        try:
            cpe_string = item['configurations']['nodes'][0]['cpe_match']
        except:
            cpe_string = ""
        
        for line in cpes:
            for cpe in line.split():
                for x in cpe_string:
                    if cpe in x.get('cpe23Uri'):
                        device_info = x.get('cpe23Uri').split(':')[4]  # Extract device information from CPE
                        message.append(slack_block_format(cpe, description, id, cve_url, severity, device_info))
                        cve_count += 1

    return message, cve_count

def slack_block_format(product, description, id, cve_url, severity, device_info):
    block = {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*Product:* {product}\n *CVE ID:* {id}\n *Description:* {description}\n *More Info:* {cve_url}\n *Severity:* {severity}\n *Device Info:* {device_info}\n"
        }
    }
    return block

# Other functions remain unchanged

def send_slack_alert(message, cve_count):
    url = os.getenv('SLACK_WEBHOOK')
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "plain_text",
                "emoji": True,
                "text": f"Hello :wave:, {cve_count} Security Vulnerabilities affecting your Tech Stack were disclosed today."
            }
        }
    ]
    blocks.extend(message)
    slack_message = {"blocks": blocks}
    x = requests.post(url, json=slack_message)

def main():
    print("VulnAlerts Using GitHub Actions\n")
    message, cve_count = parse_nvd_feed(get_cpes())
    if cve_count > 0:
        send_slack_alert(message, cve_count)
    print("Notification Sent")

if __name__ == '__main__':
    main()

