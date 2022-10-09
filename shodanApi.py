import shodan,json,datetime


with open("api_key.txt") as f:
    key = f.read().strip()

# inisialisasi buat object & masukan api key Shodan 
api = shodan.Shodan(key)

 

def bannerCount(banner):
    try:
        bannerCount = api.count(banner)
        print(f"Count {banner} : {bannerCount['total']:,}")
    except Exception as err:
        print(f"Error : {err}")

def hostInfo(host):
    try:
        host = api.host(host)

        data = f'''
### Network & Vulns Info ###
IP        : {host.get("ip_str","not found")}
Isp       : {host.get("isp","not found")}
Org       : {host.get("org","not found")}
OS        : {host.get("os","not found")}\n'''


        data += "Tags      : \n"
        
        if (len(host["tags"]) > 0) :
            for tag in host["tags"]:
                data += f"    #{tag}\n"
        else:
            data += "    Not Found\n"
            

        data += "Hostnames : \n"
        
        if (len(host["hostnames"]) > 0) :
            for hostname in host["hostnames"]:
                data += f"    - {hostname}\n"
        else:
            data += "    Not Found\n"


        data += "Domains   :\n"
        
        if (len(host["domains"]) > 0) :
            for domain in host["domains"]:
                data += f"    - {domain}\n"
        else:
            data += "    Not Found\n"


        data += f"Ports     : \n"
            
        if (len(host["ports"]) > 0) :
            for port in host["ports"]:
                data += f"    + {port}\n"
        else:
            data += "    Not Found\n"

        
        data += "Vulns     : \n"
        
        try:
            if (len(host["vulns"]) > 0) :
                for vuln in host["vulns"]:
                    data += f"   [!] {vuln}\n"
            else:
                data += "    Not Found\n"
        except:
            data += "    Not Found\n"

        data += f'''
### Location Info ###
Country   : {host.get("country_name","not found")}
City      : {host.get("city","not found")}
Code      : {host.get("region_code","not found")}
Latitude  : {host.get("latitude","not found")}
Longitude : {host.get("longitude","not found")}'''

        print(data)


        obj = {}
        ports = []

        for header in host["data"]:
            ports.append({header["port"]:header["data"]})

        obj[host.get("ip_str","n/a")] = {
            "org" : host.get("org","n/a"),
            "os" : host.get("os","n/a"),
            "tags" : host.get("tags","n/a"),
            "vulns" : host.get("vulns","n/a"),
            "isp" : host.get("isp","n/a"),
            "hostnames" : host.get("hostnames","n/a"),
            "ports" : host.get("ports","n/a"),
            "port_headers" : ports,
            "city" : host.get("city","n/a"),
            "country" : host.get("country_name","n/a"),
            "code" : host.get("region_code","n/a"),
            "latitude" : host.get("latitude","n/a"),
            "longitude" : host.get("longitude","n/a")
            }
        
        waktu = datetime.datetime.now()
        namaFile = f"{host['ip_str']}.{waktu.year}-{waktu.month}-{waktu.day}"


        with open(f"./data/{namaFile}.json","w") as f:
            f.write(json.dumps(obj, indent=3))

        with open(f"./data/{namaFile}.raw.json","w") as f:
            f.write(json.dumps(host, indent=3))

    except Exception as err:
        print(f"Error : {err}")
