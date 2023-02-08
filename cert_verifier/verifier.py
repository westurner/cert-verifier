"""
Verify blockchain certificates (http://www.blockcerts.org/)

Overview of verification steps
- Check integrity: TODO: json-ld normalizatio
- Check signature (pre-v2)
- Check whether revoked
- Check whether expired
- Check authenticity

"""
import json

from cert_core import to_certificate_model
from cert_verifier import connectors
from cert_verifier.checks import create_verification_steps
import sys


def verify_certificate(certificate_model, options={}):
    # lookup issuer-hosted information
    issuer_info = connectors.get_issuer_info(certificate_model)

    # lookup transaction information
    connector = connectors.createTransactionLookupConnector(certificate_model.chain, options)
    transaction_info = connector.lookup_tx(certificate_model.txid)

    # create verification plan
    verification_steps = create_verification_steps(certificate_model, transaction_info, issuer_info,
                                                   certificate_model.chain)

    verification_steps.execute()
    messages = []
    verification_steps.add_detailed_status(messages)
    for message in messages:
        print(message['name'] + ',' + str(message['status']))

    return messages


def verify_certificate_file(certificate_file_name, transaction_id=None, options={}):
    with open(certificate_file_name, 'rb') as cert_fp:
        certificate_bytes = cert_fp.read()
        certificate_json = json.loads(certificate_bytes.decode('utf-8'))
        certificate_model = to_certificate_model(certificate_json=certificate_json,
                                                       txid=transaction_id,
                                                       certificate_bytes=certificate_bytes)
        result = verify_certificate(certificate_model, options)
    return result


TEST_CERTIFICATES = [
    '../tests/data/2.0/valid.json',
]

def print_usage():
    print(f"{sys.argv[0]} [-h][--test] [<cert.json> [<cert_n.json>]+]")
    print("Verify Blockcerts Certificates (in Python)")
    print("")
    print("  --test -- verify certs at the paths in TEST_CERTIFICATES")
    print("")
    print("## Examples:")
    print(f"$ {sys.argv[0]} cert_to_validate.json")
    print(f"$ {sys.argv[0]} 1.json 2.json 3.json")
    print(f"$ {sys.argv[0]} --test")


def main(argv=None):
    """Verify the blockcerts in ``argv[1:]`` or verify test certificates"""
    RETCODE_OK = 0

    if argv is None:
        argv = []

    cert_paths = []
    results = []

    if len(argv) > 1:
        if '-h' in argv or '--help' in argv:
            print_usage()
            return RETCODE_OK
 
        if '-t' in argv or '--test' in argv:
            cert_paths = TEST_CERTIFICATES
        else:
            cert_paths = argv[1:]
    else:
        # TODO: Should --test be explcitly specified instead? \
        # TODO: would it be better to run pytest on --test (with @pytest.mark.parametrize in tests/)?
        print_usage()
        cert_paths = TEST_CERTIFICATES

    results = dict.fromkeys(cert_paths)
    for cert_path in cert_paths:
        results[cert_path] = result = verify_certificate_file(cert_path)
        print(f'## {cert_path}')
        print(result)


if __name__ == "__main__":
    main(argv=sys.argv)
