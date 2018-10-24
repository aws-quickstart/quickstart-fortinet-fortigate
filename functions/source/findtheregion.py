import urllib
import urllib2
import simplejson as json
def findtheregion():
    url = "http://169.254.169.254/latest/dynamic/instance-identity/document"
    req = urllib2.Request(url)
    response = urllib2.urlopen(req)
    the_page = response.read()
    meta=json.loads(the_page)
    region=meta['region']
    return region

if __name__ == '__main__':
    r=findtheregion()
    print r
