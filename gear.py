import pandas as pd
import itertools
import pandas as pd
import numpy as np
import os
import os.path
import re
from urllib.parse import urlparse
from googlesearch import search
from tld import get_tld

class Working_gears:
    def __init__(self , url):
        self.url = url

    def having_ip_address(self):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', self.url)  # Ipv6
        if match:
            # print match.group()
            return 1
        else:
            # print 'No matching pattern found'
            return 0

    def abnormal_url(self):
        hostname = urlparse(self.url).hostname
        hostname = str(hostname)
        match = re.search(hostname, self.url)
        if match:
            # print match.group()
            return 1
        else:
            # print 'No matching pattern found'
            return 0

    def google_index(self):
        site = search(self.url, 5)
        return 1 if site else 0

    def count_dot(self):
        count_dot = self.url.count('.')
        return count_dot

    def count_www(self):
        return self.url.count('www')

    def count_atrate(self):
        return self.url.count('@')

    def no_of_dir(self):
        urldir = urlparse(self.url).path
        return urldir.count('/')

    def no_of_embed(self):
        urldir = urlparse(self.url).path
        return urldir.count('//')

    def shortening_service(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                          'tr\.im|link\.zip\.net',
                          self.url)
        if match:
            return 1
        else:
            return 0

    def count_https(self):
        return self.url.count('https')

    def count_http(self):
        return self.url.count('http')

    def count_per(self):
        return self.url.count('%')

    def count_ques(self):
        return self.url.count('?')

    def count_hyphen(self):
        return self.url.count('-')

    def count_equal(self):
        return self.url.count('=')

    def url_length(self):  # Length of URL
        return len(str(self.url))

    # Hostname Length

    def hostname_length(self):
        return len(urlparse(self.url).netloc)

    def suspicious_words(self):
        match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                          self.url)
        if match:
            return 1
        else:
            return 0

    def digit_count(self):
        digits = 0
        for i in self.url:
            if i.isnumeric():
                digits = digits + 1
        return digits

    def letter_count(self):
        letters = 0
        for i in self.url:
            if i.isalpha():
                letters = letters + 1
        return letters

    # First Directory Length
    def fd_length(self):
        urlpath = urlparse(self.url).path
        try:
            return len(urlpath.split('/')[1])
        except:
            return 0

    def tld_length(self , tld):
        try:
            return len(tld)
        except:
            return -1

    def main(self):

        status = []

        status.append(self.having_ip_address())
        status.append(self.abnormal_url())
        status.append(self.count_dot())
        status.append(self.count_www())
        status.append(self.count_atrate())
        status.append(self.no_of_dir())
        status.append(self.no_of_embed())

        status.append(self.shortening_service())
        status.append(self.count_https())
        status.append(self.count_http())

        status.append(self.count_per())
        status.append(self.count_ques())
        status.append(self.count_hyphen())
        status.append(self.count_equal())

        status.append(self.url_length())
        status.append(self.hostname_length())
        status.append(self.suspicious_words())
        status.append(self.digit_count())
        status.append(self.letter_count())
        status.append(self.fd_length())
        tld = get_tld(self.url, fail_silently=True)

        status.append(self.tld_length(tld))

        return np.array(status).reshape((1,-1))

    def get_prediction_from_url(self):
        features_test = self.main(self.url)
        # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.
        features_test = np.array(features_test).reshape((1, -1))

        pred = lgb.predict(features_test)
        if int(pred[0]) == 0:
            res = "SAFE"
            return res

        elif int(pred[0]) == 1.0:
            res = "DEFACEMENT"
            return res

        elif int(pred[0]) == 2.0:
            res = "PHISHING"
            return res

        elif int(pred[0]) == 3.0:
            res = "MALWARE"
            return res

