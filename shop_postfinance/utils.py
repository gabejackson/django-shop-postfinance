#-*- coding: utf-8 -*-

from django.conf import settings
import hashlib

def security_check(data, secret_key):
    '''
    Performs a postfinance security check. That is, it compares the SHA1 provided by the request to
    a SHA1 sum of the parameters (passed via GET or POST), ordered alphabetically, and separated by the
    secret key. Beware, the secret key (SHA-OUT) here may differ from the SHA-IN, check your SHA-OUT key
    in the e-payment backend: Konfiguration -> Technische Informationen -> Transaktions-Feedback ->
    Sicherheit der Anfrageparameter -> SHA-1-OUT Signatur

    Data should be a dictionary, as provided by a request's POST or GET
    '''
    original = data['SHASIGN']
    hash_string = ""
    contents = dict([(key.upper(), value) for key, value in data.items()])
    for key, value in sorted(contents.items()):
        if key != 'SHASIGN':
            hash_string += "%s=%s%s" % (key, value, secret_key)
    output = hashlib.sha1(hash_string).hexdigest().upper()
    return output == original


def compute_security_checksum(**data):
    ''' Used to send a security checksum of parameters to postfinance '''
    secret_key = settings.POSTFINANCE_SECRET_KEY
    contents = dict([(key.upper(), value) for key, value in data.items()])
    hash_string = ""
    for key, value in sorted(contents.items()):
        hash_string += "%s=%s%s" % (key, value, secret_key)
    output = hashlib.sha1(hash_string).hexdigest().upper()
    return output
