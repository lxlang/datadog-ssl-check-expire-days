import time
import datetime
import subprocess
import sys
from checks import AgentCheck

class SSLCheckExpireDays(AgentCheck):
    def name_matches(self, url):
        p = subprocess.Popen(
            "echo | openssl s_client -showcerts -servername " + url + " -connect " + url + ":443 2> /dev/null | openssl x509 -noout -checkhost " + url + "  2> /dev/null ",
            stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()

        if "does match certificate" in output:
            return True

        return False

    def expire_in_days(self, url):
        command = "echo | openssl s_client -showcerts -servername " + url + " -connect " + url + ":443 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -f 2 -d\= | xargs -0 -I arg date -d arg \"+%s\""
        p = subprocess.Popen(
            command,
            stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()

        if output:
            output = output.rstrip("\n")
            d0 = int(time.time())
            d1 = int(output)
            delta = d1 - d0
            valid_days = delta / 24 / 60 / 60  # convert the timestamp to days
            return int(valid_days)

        else:
            return -1

    def check(self, instance):
        metric = "ssl.expire_in_days"
        site = instance['site']
        tag = "site:" + site

        if not self.name_matches(site):
            # mark cname check as CRITICAL
            self.service_check("ssl.cname", status=AgentCheck.CRITICAL, tags=[tag])
            pass

        else:
            # mark cname as valid
            self.service_check("ssl.cname", status=AgentCheck.OK, tags=[tag])
            days = self.expire_in_days(site)
            self.gauge(metric, days, tags=[tag])
