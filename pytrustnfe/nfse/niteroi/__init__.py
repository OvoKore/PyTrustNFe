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
    conn1 = http.client.HTTPSConnection("api.pushover.net:443")
    conn2 = http.client.HTTPSConnection("api.pushover.net:443")
    conn3 = http.client.HTTPSConnection("api.pushover.net:443")

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

    cabecalho = '''<cabecalho versao="2.03" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="http://www.abrasf.org.br/nfse.xsd">
  <versaoDados>2.03</versaoDados>
</cabecalho>'''

    try:
        response = getattr(client.service, method)(cabecalho, xml_send)
    except suds.WebFault as e:

        conn1.request("POST", "/1/messages.json",
        urllib.parse.urlencode({
            "token": "awh6fto25b9ybi6h2zsjojsscva3ta",
            "user": "u81m6vngzsq751uw6qoywu6j7pqzhc",
            "title": "except-sent_xml",
            "message": str(xml_send),
        }), { "Content-type": "application/x-www-form-urlencoded" })
        conn1.getresponse()

        conn2.request("POST", "/1/messages.json",
        urllib.parse.urlencode({
            "token": "awh6fto25b9ybi6h2zsjojsscva3ta",
            "user": "u81m6vngzsq751uw6qoywu6j7pqzhc",
            "title": "except-received_xml",
            "message": str(e.fault.faultstring),
        }), { "Content-type": "application/x-www-form-urlencoded" })
        conn2.getresponse()

        return {
            'sent_xml': str(xml_send),
            'received_xml': str(e.fault.faultstring),
            'object': None
        }

    response, obj = sanitize_response(response)

    conn1.request("POST", "/1/messages.json",
    urllib.parse.urlencode({
        "token": "awh6fto25b9ybi6h2zsjojsscva3ta",
        "user": "u81m6vngzsq751uw6qoywu6j7pqzhc",
        "title": "sent_xml",
        "message": str(xml_send),
    }), { "Content-type": "application/x-www-form-urlencoded" })
    conn1.getresponse()

    conn2.request("POST", "/1/messages.json",
    urllib.parse.urlencode({
        "token": "awh6fto25b9ybi6h2zsjojsscva3ta",
        "user": "u81m6vngzsq751uw6qoywu6j7pqzhc",
        "title": "received_xml",
        "message": str(response),
    }), { "Content-type": "application/x-www-form-urlencoded" })
    conn2.getresponse()

    conn3.request("POST", "/1/messages.json",
        urllib.parse.urlencode({
            "token": "awh6fto25b9ybi6h2zsjojsscva3ta",
            "user": "u81m6vngzsq751uw6qoywu6j7pqzhc",
            "title": "object",
            "message": str(len(obj)),
        }), { "Content-type": "application/x-www-form-urlencoded" })
    conn3.getresponse()

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
