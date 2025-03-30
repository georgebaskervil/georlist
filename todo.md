readd     
{
  "name": "Anti-malware",
  "type": "hosts",
  "source": "https://raw.githubusercontent.com/iam-py-test/my_filters_001/main/Alternative%20list%20formats/antimalware_adguard_home.txt",
  "transformations": ["Compress", "ValidateAllowIp"]
}, 
once the bad include rule is fixed

findout why 
{
    "name": "ISC SANS Shodan",
    "type": "hosts",
    "source": "https://isc.sans.edu/api/threatlist/shodan/shodan.txt",
    "transformations": ["Compress", "ValidateAllowIp"]
},
is xml not txt