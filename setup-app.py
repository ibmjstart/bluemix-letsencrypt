import requests
import json
import yaml
from subprocess import call, check_call, Popen, PIPE
import sys
import time

# Define some helper functions

def domain_has_ssl(domain, full_host, print_info=False):
    """domain_has_ssl uses the two most-reliable ways to check for an SSL on
    a domain name within bluemix. It calls the Bluemix CLI to ask for
    certificate details, and it attempts to connect to that host with HTTPS.
    If either succeeds, it returns True. Otherwise, it returns false. Note
    that it is possible to get false negatives, but not false positives.
    The print_info parameter can be used to dump the certificate information
    from Bluemix to stdout.
    """
    pipe = Popen("ibmcloud app domain-cert %s" % domain,
                 stdout=PIPE, shell=True)
    output = pipe.stdout.read().decode("unicode_escape")
    cert_exists = "OK" in output
    if print_info and cert_exists:
        print(output)
    return cert_exists or check_ssl(full_host)

def get_cert(appname, domain, certname):
    """get_cert wraps the `ibmcloud cf ssh` command to retrieve the literal file
    contents of the certificate that was requested.
    It then writes the certificate to a file in the current working
    directory with the same name that the certificate had on the server.
    """
    command = "ibmcloud cf --quiet ssh %s -c \"cat ~/app/conf/live/%s/%s\"" % (appname, domain, certname)
    print("Running: %s" % command)
    certfile = open(certname,"w+")
    return Popen(command, shell=True, stdout=certfile)

def check_ssl(full_host):
    """check_ssl makes an HTTPS request to a given full host name
    and returns a boolean for whether the SSL on the host is present
    and valid.
    """
    try:
        target = "https://%s" % full_host
        print("Making GET request to %s" % target)
        requests.get(target)
        return True
    except requests.exceptions.SSLError as err:
        print(err)
        return False

# Begin Script
with open('domains.json') as data_file:
    settings = json.load(data_file)

with open('manifest.yml') as manifest_file:
    manifest = yaml.safe_load(manifest_file)

appname = manifest['applications'][0]['name']

#consider deleting the app if you've already pushed it with recent success
#otherwise the script can get confused by those success messages in the logs
#call(["ibmcloud", "cf", "delete", appname])

# Push the app, but don't start it yet
check_call(["ibmcloud", "app", "push", "--no-start"])

# For each domain, map a route for the specific letsencrypt check path
# '/.well-known/acme-challenge/'
for entry in settings['domains']:
    domain = entry['domain']
    for host in entry['hosts']:
        if host == '.':
            call(["ibmcloud", "cf", "map-route", appname, domain, "--path", ".well-known/acme-challenge/"])
        else:
            call(["ibmcloud", "cf", "map-route", appname, domain, "--hostname", host, "--path", ".well-known/acme-challenge/"])

# Now the app can be started
check_call(["ibmcloud", "app", "start", appname])

# Tail the application log
print("Parsing log files.")
end_token = "cf stop %s" % appname  # Seeing this in the log means certs done
log_pipe = Popen("ibmcloud cf logs %s --recent" % appname, shell=True,
                 stdout=PIPE, stderr=PIPE)
log_lines = str(log_pipe.stdout.readlines())

print("Waiting for certs...")
seconds_waited = 0
MAX_WAIT_SECONDS = 60
while end_token not in ''.join(log_lines)\
        and seconds_waited < MAX_WAIT_SECONDS:
    # Keep checking the logs for cert readiness
    print("Certs not ready yet, retrying in 5 seconds.")
    time.sleep(5)
    seconds_waited = seconds_waited + 5
    log_pipe = Popen("ibmcloud cf logs %s --recent" % appname, shell=True,
                     stdout=PIPE, stderr=PIPE)
    log_lines = str(log_pipe.stdout.readlines())

# If no certs in log after MAX_WAIT_SECONDS, exit and warn user
if seconds_waited >= MAX_WAIT_SECONDS:
    print("\n\nIt has been %d minutes without seeing certificates issued"
          % (MAX_WAIT_SECONDS/60)
          + " in the log. Something probably went wrong. Please check"
          + " the output of `ibmcloud cf logs %s --recent`" % appname
          + " for more information.\n\nExiting.")
    sys.exit(1)

# Figure out which domain name to look for
primary_domain = settings['domains'][0]['domain']

domain_with_first_host = "%s.%s" % (settings['domains'][0]['hosts'][0],
                                    primary_domain)

# Hostname is sometimes '.', which requires special handling
if domain_with_first_host.startswith('..'):
    domain_with_first_host = domain_with_first_host[2:]

print("\nWaiting for container to mount filesystem")
time.sleep(5)

cert1Proc = get_cert(appname, domain_with_first_host, 'cert.pem')
cert2Proc = get_cert(appname, domain_with_first_host, 'chain.pem')
cert3Proc = get_cert(appname, domain_with_first_host, 'fullchain.pem')
cert4Proc = get_cert(appname, domain_with_first_host, 'privkey.pem')

# wait for get_cert subprocesses to finish
cert1Proc.wait()
cert2Proc.wait()
cert3Proc.wait()
cert4Proc.wait()

# Check if there is already an SSL in place
if domain_has_ssl(primary_domain, domain_with_first_host, True):
    print("\n***IMPORTANT***")
    print("This domain name already has an SSL certificate in bluemix."
          + " You must first remove the old SSL before adding a new one."
          + " This means that your application will have a window of time"
          + " without a certificate.\n")
    print("If you wish to continue, run:\n"
          + ("ibmcloud app domain-cert-remove %s; " % primary_domain)
          + ("ibmcloud app domain-cert-add %s -c cert.pem -k privkey.pem -i chain.pem; "
             % primary_domain)
          + ("ibmcloud app domain-cert %s\n" % primary_domain))
    sys.exit(1)

# Kill the letsencrypt app now that its work is done
call(["ibmcloud", "app", "stop", appname])

failure = True
count = 0
while(failure and count < 3):
    # Upload new cert
    print("Attempting certificate upload...")
    call("ibmcloud app domain-cert-add %s -c cert.pem -k privkey.pem -i chain.pem"
         % primary_domain, shell=True)
    failure = not domain_has_ssl(primary_domain, domain_with_first_host, True)
    count = count + 1
    time.sleep(5)

print("Warning: Please note that your SSL certificate, its corresponding"
      + " PRIVATE KEY, and its intermediate certificates have been downloaded"
      + " to the current working directory. If you need to remove them, use"
      + " `rm *.pem`")
if failure:
    print("Unable to upload certificates")
    sys.exit(1)

print("Upload Succeeded")
