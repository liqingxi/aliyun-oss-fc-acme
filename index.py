#!/usr/bin/env python3
# Copyright Daniel Roesler, under MIT license, see LICENSE at github.com/diafygi/acme-tiny
import subprocess, json, base64, time, hashlib, re, logging
from urllib.request import urlopen, Request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

import config

DEFAULT_CA = "https://acme-v02.api.letsencrypt.org" # DEPRECATED! USE DEFAULT_DIRECTORY_URL INSTEAD
# DEFAULT_CA = "https://acme-staging-v02.api.letsencrypt.org"  # DEPRECATED! USE DEFAULT_DIRECTORY_URL INSTEAD
DEFAULT_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
# DEFAULT_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)
directory_url = DEFAULT_DIRECTORY_URL
log = LOGGER
CA = DEFAULT_CA
directory, acct_headers, alg, jwk, account_key = None, None, None, None, None  # global variables


# helper functions - dump private key to PEM
def _dump_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


# helper functions - generate ecc private key
def _generate_rsa_key(KEY_SIZE = 2048):
    return rsa.generate_private_key(public_exponent=65537,
                            key_size=KEY_SIZE,
                            backend=default_backend())


# helper functions - generate ecc private key
def _generate_ec_key(curve = ec.SECP256R1()):
    return ec.generate_private_key(
             curve, default_backend())

# print(_dump_key(_generate_ec_key()).decode('utf-8'))


# helper functions - base64 encode for jose spec
def _b64(b):
    return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")


# helper function - run external commands
def _cmd(cmd_list, stdin=None, cmd_input=None, err_msg="Command Line Error"):
    proc = subprocess.Popen(cmd_list, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(cmd_input)
    if proc.returncode != 0:
        raise IOError("{0}\n{1}".format(err_msg, err))
    return out


# helper function - make request and automatically parse json response
def _do_request(url, data=None, err_msg="Error", depth=0):
    try:
        resp = urlopen(
            Request(url, data=data, headers={"Content-Type": "application/jose+json", "User-Agent": "acme-tiny"}))
        resp_data, code, headers = resp.read().decode("utf8"), resp.getcode(), resp.headers
    except IOError as e:
        resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
        code, headers = getattr(e, "code", None), {}
    try:
        resp_data = json.loads(resp_data)  # try to parse json results
    except ValueError:
        pass  # ignore json parsing errors
    if depth < 100 and code == 400 and resp_data['type'] == "urn:ietf:params:acme:error:badNonce":
        raise IndexError(resp_data)  # allow 100 retrys for bad nonces
    if code not in [200, 201, 204]:
        raise ValueError(
            "{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(err_msg, url, data, code, resp_data))
    return resp_data, code, headers


# helper function - make signed requests
def _send_signed_request(url, payload, err_msg, depth=0):
    payload64 = "" if payload is None else _b64(json.dumps(payload).encode('utf8'))
    new_nonce = _do_request(directory['newNonce'])[2]['Replay-Nonce']
    protected = {"url": url, "alg": alg, "nonce": new_nonce}
    protected.update({"jwk": jwk} if acct_headers is None else {"kid": acct_headers['Location']})
    protected64 = _b64(json.dumps(protected).encode('utf8'))
    protected_input = "{0}.{1}".format(protected64, payload64).encode('utf8')

    signature = account_key.sign(
        protected_input,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    data = json.dumps({"protected": protected64, "payload": payload64, "signature": _b64(signature)})
    try:
        return _do_request(url, data=data.encode('utf8'), err_msg=err_msg, depth=depth)
    except IndexError:  # retry bad nonces (they raise IndexError)
        return _send_signed_request(url, payload, err_msg, depth=(depth + 1))


# helper function - poll until complete
def _poll_until_not(url, pending_statuses, err_msg):
    result, t0 = None, time.time()
    while result is None or result['status'] in pending_statuses:
        assert (time.time() - t0 < 3600), "Polling timeout"  # 1 hour timeout
        time.sleep(0 if result is None else 2)
        result, _, _ = _send_signed_request(url, None, err_msg)
    return result


def _build_csr(domains):
    private_key = serialization.load_pem_private_key(config.CERT_KEY_PEM, password=None, backend=default_backend())
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
    ]))
    # builder = builder.add_extension(
    #      x509.BasicConstraints(ca=False, path_length=None), critical=True,
    # )
    builder = builder.add_extension(x509.SubjectAlternativeName(
        list(map(x509.DNSName, domains))),
        critical=False
    )
    csr = builder.sign(
        private_key, hashes.SHA256(), default_backend()
    )
    return csr


def main():
    global directory, account_key, jwk, alg, acct_headers

    # parse account key to get public key
    log.info("Parsing account key...")
    account_key = serialization.load_pem_private_key(config.ACC_KEY_PEM, password=None, backend=default_backend())
    pub_num = account_key.public_key().public_numbers()

    alg = "RS256"
    jwk = {
        "e": _b64(pub_num.e.to_bytes(3, 'big', signed=False)),
        "kty": "RSA",
        "n": _b64(pub_num.n.to_bytes(account_key.key_size // 8, 'big', signed=False)),
    }
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())

    # get the ACME directory of urls
    log.info("Getting directory...")
    # directory_url = CA + "/directory" if CA != DEFAULT_CA else directory_url  # backwards compatibility with deprecated CA kwarg
    directory, _, _ = _do_request(directory_url, err_msg="Error getting directory")
    log.info("Directory found!")

    # create account, update contact details (if any), and set the global key identifier
    log.info("Registering account...")
    reg_payload = {"termsOfServiceAgreed": True}
    account, code, acct_headers = _send_signed_request(directory['newAccount'], reg_payload, "Error registering")
    log.info("Registered!" if code == 201 else "Already registered!")
    # if contact is not None:
    #     account, _, _ = _send_signed_request(acct_headers['Location'], {"contact": contact}, "Error updating contact details")
    #     log.info("Updated contact details:\n{0}".format("\n".join(account['contact'])))

    # find domains
    for domain_config in config.DOAMIN_LIST:

        domains = domain_config['DOMAIN']
        domains_auth = domain_config['HANDLE']
        log.info("Found domains: {0}".format(", ".join(domains)))

        log.info("Generating CSR...")
        try:
            csr = _build_csr(domains) if domain_config['CERT_CSR'] == None else x509.load_pem_x509_csr(domain_config['CERT_CSR'], backend=default_backend())
            assert isinstance(csr, x509.CertificateSigningRequest)
        except AssertionError as e:
            raise AssertionError("Cannot build CSR or load CSR from config")
        log.info("CSR generated!")

        # create a new order
        log.info("Creating new order...")
        order_payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
        order, _, order_headers = _send_signed_request(directory['newOrder'], order_payload, "Error creating new order")
        log.info("Order created!")

        # get the authorizations that need to be completed
        for auth_url in order['authorizations']:
            authorization, _, _ = _send_signed_request(auth_url, None, "Error getting challenges")
            domain = authorization['identifier']['value']
            log.info("Verifying {0}...".format(domain))

            # find the http-01 challenge and write the challenge file
            challenge = [c for c in authorization['challenges'] if c['type'] == "http-01"][0]
            token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
            keyauthorization = "{0}.{1}".format(token, thumbprint)
            log.info(f'token {token} authorization {keyauthorization} ')

            domains_auth.add_auth_file(token, keyauthorization)

            try:
                wellknown_url = "http://{0}/.well-known/acme-challenge/{1}".format(domain, token)
                assert _do_request(wellknown_url)[0] == keyauthorization
            except (AssertionError, ValueError) as e:
                raise ValueError("couldn't download {0}: {1}".format(wellknown_url, e))

            # say the challenge is done
            _send_signed_request(challenge['url'], {}, "Error submitting challenges: {0}".format(domain))
            authorization = _poll_until_not(auth_url, ["pending"], "Error checking challenge status for {0}".format(domain))
            if authorization['status'] != "valid":
                raise ValueError("Challenge did not pass for {0}: {1}".format(domain, authorization))
            # os.remove(wellknown_path)
            domains_auth.remove_auth_file(token)

            log.info("{0} verified!".format(domain))

        # finalize the order with the csr
        log.info("Signing certificate...")
        # csr_der = _cmd(["openssl", "req", "-in", csr, "-outform", "DER"], err_msg="DER Export Error")
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        _send_signed_request(order['finalize'], {"csr": _b64(csr_der)}, "Error finalizing order")

        # poll the order to monitor when it's done
        order = _poll_until_not(order_headers['Location'], ["pending", "processing"], "Error checking order status")
        if order['status'] != "valid":
            raise ValueError("Order failed: {0}".format(order))

        # download the certificate
        certificate_pem, _, _ = _send_signed_request(order['certificate'], None, "Certificate download failed")
        log.info("Certificate signed!")
        domains_auth.save_cert(certificate_pem)
        log.info("Certificate saved!")
        log.info(certificate_pem)


def handler(event, context):
    main()


if __name__ == "__main__":
    main()