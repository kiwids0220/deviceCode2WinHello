import argparse
import sys
import base64
import pprint
import random
import string
import requests
import codecs
import time
import json
from urllib.parse import quote_plus 
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as apadding
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.utils import CryptographyDeprecationWarning
from roadtools.roadlib.auth import Authentication, WELLKNOWN_CLIENTS, WELLKNOWN_RESOURCES
from roadtools.roadtx.selenium import SeleniumAuthentication
from roadtools.roadlib.deviceauth import DeviceAuthentication

Description = "DeviceCode2WinHelloForBusiness is a small script that automates the registration flow for WFB key with a device code auth or a user provided refresh token."

class deviceCode2WFH(Authentication,DeviceAuthentication):
    """
    Automation
    """
    def __init__(self, username=None, password=None, tenant=None, client_id=WELLKNOWN_CLIENTS["broker"]):
        Authentication.__init__(self, username, password, tenant, client_id)
        DeviceAuthentication.__init__(self, auth=self)

    ### Hard-coding the clientID because this is the only client can request PRT with its refresh token...
    def device_code_wrapper(self):
        print("[*] Kicking off Device Code Auth flow with client id: " + self.client_id + " and resource: " + self.resource_uri)
        token_data = self.authenticate_device_code()
        return token_data
    
    def register_device_wrapper(self, access_token, jointype=0, certout=None, privout=None, device_type=None, device_name=None, os_version=None, deviceticket=None):
        # Fill in names if not supplied
        if not device_name:
            device_name = 'DESKTOP-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

        if not certout:
            certout = device_name.lower() + '.pem'

        if not privout:
            privout = device_name.lower() + '.key'

        if not device_type:
            device_type = "Windows"

        if not os_version:
            os_version = "10.0.19041.928"

        # Generate our key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # Write device key to disk
        print(f'Saving private key to {privout}')
        with open(privout, "wb") as keyf:
            keyf.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        # Generate a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "7E980AD9-B86D-4306-9425-9AC066FB014A"),
        ])).sign(key, hashes.SHA256())

        # Get parameters needed to construct the CNG blob
        certreq = csr.public_bytes(serialization.Encoding.DER)
        certbytes = base64.b64encode(certreq)

        pubkeycngblob = base64.b64encode(self.create_pubkey_blob_from_key(key))


        if device_type.lower() == 'macos':
            data = {
              "DeviceDisplayName" : device_name,
              "CertificateRequest" : {
                "Type" : "pkcs10",
                "Data" : certbytes.decode('utf-8')
              },
              "OSVersion" : "12.2.0",
              "TargetDomain" : "iminyour.cloud",
              "AikCertificate" : "",
              "DeviceType" : "MacOS",
              "TransportKey" : base64.b64encode(self.create_public_jwk_from_key(key, True).encode('utf-8')).decode('utf-8'),
              "JoinType" : jointype,
              "AttestationData" : ""
            }
        else:
            data = {
                "CertificateRequest":
                    {
                        "Type": "pkcs10",
                        "Data": certbytes.decode('utf-8')
                    },
                "TransportKey": pubkeycngblob.decode('utf-8'),
                # Can likely be edited to anything, are not validated afaik
                "TargetDomain": "iminyour.cloud",
                "DeviceType": device_type,
                "OSVersion": os_version,
                "DeviceDisplayName": device_name,
                "JoinType": jointype,
                "attributes": {
                    "ReuseDevice": "true",
                    "ReturnClientSid": "true"
                }
            }
            # Add device ticket if requested
            if deviceticket:
                data['attributes']['MSA-DDID'] = base64.b64encode(deviceticket.encode('utf-8')).decode('utf-8')


        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        print('Registering device')
        res = requests.post('https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=2.0', json=data, headers=headers, proxies=self.proxies, verify=self.verify)
        returndata = res.json()
        if not 'Certificate' in returndata:
            print('Error registering device! Got response:')
            pprint.pprint(returndata)
            return False
        cert = x509.load_der_x509_certificate(base64.b64decode(returndata['Certificate']['RawBody']))
        # There is only one, so print it
        for attribute in cert.subject:
            print(f"Device ID: {attribute.value}")
        with open(certout, "wb") as certf:
            certf.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f'Saved device certificate to {certout}')
        #returning the certificate and private key to use them next instead of reading from disk everytime
        return cert.public_bytes(serialization.Encoding.PEM), key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        
    def register_entraid_devices(self):
        print("[*] Registering azuread devices")
        print("[*] Asking for another token for device registration resource: " + WELLKNOWN_RESOURCES["devicereg"])
        self.resource_uri=WELLKNOWN_RESOURCES["devicereg"]
        devicereg_token = self.authenticate_with_refresh_native(self.refresh_token, client_secret=self.password)
        #A quick sanity check on the device registration token
        if devicereg_token:
            _, tokendata = self.parse_accesstoken(devicereg_token["accessToken"])
            if tokendata['aud'] != 'urn:ms-drs:enterpriseregistration.windows.net':
                    print(f"Wrong token audience, got {tokendata['aud']} but expected: urn:ms-drs:enterpriseregistration.windows.net")
                    print("Make sure to request a token with -r urn:ms-drs:enterpriseregistration.windows.net")
                    return
            else:
                print("[✔] Got the device reg token! Trying to JOIN a new device to Entra ID now!")
                #joi type 0 stands for JOIN, 4 stands for register
                return self.register_device_wrapper(devicereg_token["accessToken"], jointype=0)

    def loadcert_in_mem(self, pemfile, privkeyfile):
        self.certificate = x509.load_pem_x509_certificate(pemfile)
        # We used the same key for transport key and the device key
        self.transportkeydata = self.keydata = privkeyfile
        self.transportprivkey = self.privkey = serialization.load_pem_private_key(self.keydata, password=None)
        return True
    
    def refreshtoken_to_prt_wrapper(self, msbroker_token):
        print("[*] requesting new PRT with Entra ID using refresh token that we request previously as client 'msbroker': " + WELLKNOWN_CLIENTS["broker"])
        prtdata = self.get_prt_with_refresh_token(msbroker_token["refreshToken"])
        return prtdata
    
    def windows_hello_for_business(self, username, driver_path, proxy):
        self.set_client_id('dd762716-544d-4aeb-a526-687b73838a22')
        hint = '&login_hint=' + quote_plus(username)
    
        # Get ngcmfa token for device registration service
        replyurl = "ms-appx-web://Microsoft.AAD.BrokerPlugin/dd762716-544d-4aeb-a526-687b73838a22"
        url = f'https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=dd762716-544d-4aeb-a526-687b73838a22&redirect_uri=ms-appx-web%3a%2f%2fMicrosoft.AAD.BrokerPlugin%2fdd762716-544d-4aeb-a526-687b73838a22&resource=urn%3ams-drs%3aenterpriseregistration.windows.net&add_account=noheadsup&scope=openid{hint}&response_mode=form_post&windows_api_version=2.0&amr_values=ngcmfa'
        selauth = SeleniumAuthentication(self, self, replyurl, proxy=proxy)
        selauth.headless=False
        service = selauth.get_service(driver_path)
        selauth.driver = selauth.get_webdriver(service, intercept=True)
        tokenreply = selauth.selenium_enrich_prt(url)
        self.tokendata = self.tokenreply_to_tokendata(tokenreply)
        self.outfile = ".roadtools_auth"
        with codecs.open(self.outfile, 'w', 'utf-8') as outfile:
                json.dump(self.tokendata, outfile)
                print('Tokens were written to {}'.format(self.outfile))
        tokenobject, tokendata = self.parse_accesstoken(self.tokendata["accessToken"])
        key, pubkeycngblob = self.create_hello_key()
        result = self.register_winhello_key(pubkeycngblob, tokenobject['accessToken'])
        print(result) 
           
def main():
    parser = argparse.ArgumentParser(add_help=True, description=Description, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-p', '--proxy', action='store', help="Proxy requests through a proxy (format: proxyip:port). Ignores TLS validation if specified, unless --secure is used.")
    parser.add_argument('-s', '--secure', action='store_true', help="Enforce certificate validation even if using a proxy")

    #User can provide a refresh token to any resource as the client 'msbroker'
    parser.add_argument('-r', '--refresh-token', action='store', help='Refresh token for device registration service.' + WELLKNOWN_CLIENTS['broker'])
    #AzureAD Device join/registration prep if the user doesn't have one ready to go..
    parser.add_argument('-c', '--cert-pem', action='store', metavar='file', help='Certificate file with device certificate (if not provided, the script will try to join a device to AzureAD for you)')
    parser.add_argument('-k', '--key-pem', action='store', metavar='file', help='Private key file for device  (if not provided, the script will try to join a device to AzureAD for you)')
    parser.add_argument('--cert-pfx', action='store', metavar='file', help='Device cert and key as PFX file  (if not provided, the script will try to join a device to AzureAD for you)')
    parser.add_argument('--pfx-pass', action='store', metavar='password', help='PFX file password')
    parser.add_argument('--pfx-base64', action='store', metavar='BASE64', help='PFX file as base64 string  (if not provided, the script will try to join a device to AzureAD for you)')

    parser.add_argument('-f', '--prt-file', action='store', metavar='FILE', help='PRT file path for saving/loading the PRT on disk')

    # WFB registration flag
    parser.add_argument('-u', '--username', action='store', metavar='USER', help='User to authenticate')
    parser.add_argument('--wfb', '-w', action='store_true', help='Attempt to register a windows hello for business key with the PRT')
    parser.add_argument('-d', '--driver-path',
                                action='store',
                                help='Path to geckodriver file on disk (download from: https://github.com/mozilla/geckodriver/releases)')
    args = parser.parse_args()
    
    seleniumproxy = None

    
    ### User can provide us with a refresh token with the client being 'msbroker'
    action = deviceCode2WFH()
    
    if args.proxy:
        action.proxies = {
            'https': f'http://{args.proxy}'
        }
        seleniumproxy = f'http://{args.proxy}'
        if not args.secure:
            action.verify = False
            
            
    if args.refresh_token:
        action.refresh_token = args.refresh_token
    else:
        token = action.device_code_wrapper()
        action.refresh_token = token["refreshToken"]
    
    ### If user already have a device joined/registered with AzureAD, we can just use the cert they provided
    if args.cert_pem and args.key_pem:
        print("[*] Using user provided certs and private keys")
        action.loadcert(args.cert_pem, args.key_pem, args.cert_pfx, args.pfx_pass, args.pfx_base64)

    elif args.cert_pfx or args.pfx_pass or args.pfx_pass:
        action.loadcert(args.cert_pem, args.key_pem, args.cert_pfx, args.pfx_pass, args.pfx_base64)
    else:
        certpem, privkey = action.register_entraid_devices()
        action.loadcert_in_mem(certpem, privkey)
  
    prtdata = action.refreshtoken_to_prt_wrapper(token)
    if prtdata:
        print("[✔] Congratulations! You got a new PRT!")
        action.saveprt(prtdata, prtfile="roadtx.prt")
        action.setprt(prtdata["refresh_token"], prtdata['session_key'])
    if args.wfb:
        if not args.username:
            print("You will need to supply the username")
        action.windows_hello_for_business(args.username, driver_path=args.driver_path, proxy=seleniumproxy)
        
if __name__ == '__main__':
    main()
