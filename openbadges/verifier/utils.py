import sys
from collections import OrderedDict
from urllib.parse import urlparse

import hashlib
import json
import requests
import requests_cache
import string
from pyld.jsonld import JsonLdError

MESSAGE_LEVEL_ERROR = 'ERROR'
MESSAGE_LEVEL_WARNING = 'WARNING'
MESSAGE_LEVEL_INFO = 'INFO'
MESSAGE_LEVELS = (MESSAGE_LEVEL_ERROR, MESSAGE_LEVEL_WARNING, MESSAGE_LEVEL_INFO,)


class CachableDocumentLoader(object):
    def __init__(self, use_cache=False, backend='memory', expire_after=300, session=None):
        self.use_cache = use_cache
        self.contexts = set()

        if session is not None:
            self.session = session
        elif self.use_cache:
            self.session = requests_cache.CachedSession(backend=backend, expire_after=expire_after)
        else:
            self.session = requests.Session()

    def __call__(self, url):
        try:
            # validate URLs
            pieces = urlparse(url)
            if (not all([pieces.scheme, pieces.netloc]) or
                    pieces.scheme not in ['http', 'https'] or
                    set(pieces.netloc) > set(string.ascii_letters + string.digits + '-.:')):
                raise JsonLdError(
                    'Could not dereference URL; can only load URLs using',
                    'the "http" and "https" schemes.',
                    'jsonld.InvalidUrl', {'url': url},
                    code='loading document failed')

            response = self.session.get(
                url, headers={'Accept': 'application/ld+json, application/json'})

            doc = {'contextUrl': None, 'documentUrl': url, 'document': response.text}

            if self.use_cache:
                doc['from_cache'] = response.from_cache
                self.session.remove_expired_responses()

            # Save URL for Potential Extension contexts.
            try:
                data = json.loads(response.text)
                context = data['@context']
                if any([isinstance(el, dict) for el in list_of(context)]):
                    self.contexts.update([url])
            except Exception:
                pass

            return doc

        except JsonLdError as e:
            raise e
        except Exception as cause:
            raise JsonLdError(
                'Could not retrieve JSON-LD document from URL.',
                'jsonld.LoadDocumentError',
                code='loading document failed',
                cause=cause)


jsonld_use_cache = {'documentLoader': CachableDocumentLoader(use_cache=True)}
jsonld_no_cache = {'documentLoader': CachableDocumentLoader(use_cache=False)}


def list_of(value):
    if value is None:
        return []
    elif isinstance(value, list):
        return value
    return [value]


def identity_hash(identfier, salt='', alg='sha256'):
    if not sys.version[:3] < '3':
        identfier = identfier.encode()
        salt = salt.encode()
    if alg == 'sha256':
        return alg + '$' + hashlib.sha256(identfier + salt).hexdigest()
    elif alg == 'md5':
        return alg + '$' + hashlib.md5(identfier + salt).hexdigest()
    raise ValueError("Alg {} not supported.".format(alg))


def make_string_from_bytes(input_value):
    if isinstance(input_value, bytes):
        return input_value.decode()
    return input_value


def get_badgeclass(verification_results):
    for value in verification_results['graph']:
        if value.get('type', '') == 'BadgeClass':
            return value


def get_issuer(verification_results):
    for value in verification_results['graph']:
        if value.get('type', '') == 'Issuer':
            return value


def get_assertion(verification_results):
    for value in verification_results['graph']:
        if value.get('type', '') == 'Assertion':
            return value


def get_assertion_image(verification_results, assertion_image_url):
    if assertion_image_url:
        original_json = verification_results.get('input', {}).get('original_json')
        if original_json and assertion_image_url in original_json:
            return original_json[assertion_image_url]


error_explanations = {
    "DETECT_AND_VALIDATE_NODE_CLASS": "This most likely means that this Badge is set to private by the receiver. Please ask the receiver to set it to public. If this is not the case, then this Badge is not hosted anymore and cannot be verified.",
    "ASSERTION_TIMESTAMP_CHECKS": "This means the Badge has expired and is not valid anymore.",
    "JSONLD_COMPACT_DATA": "The context could not be expanded by JSON LD. Most likely there are extensions in the badge class that are not published or not are hosted anymore."
}


def add_error_explanation(errors):
    explanation = ""
    for error in errors:
        for key in error_explanations.keys():
            if error['name'] == key:
                explanation = error_explanations[key]
    error['explanation'] = explanation


def get_errors(verification_results):
    report = verification_results.get('report', False)
    if report:
        if not report.get('valid'):
            messages = report.get('messages')
            add_error_explanation(messages)
            return messages


def override_eduid_error(report):
    # make sure uri format check failure will pass
    if report['errorCount'] > 0:
        error_messages = []
        for message in report['messages']:
            if 'not valid in unknown type node' in message['result']:  # = uri format validity check fail
                error_messages.append(message)
        for error_message in error_messages:
            report['messages'].remove(error_message)
            report['errorCount'] -= 1



def get_extensions(verification_results):
    original_json = verification_results.get('input', {}).get('original_json')
    # Loop though all the extensions, without knowing the keys lead to them.
    # The keys might differ, because they're urls.
    if original_json:
        extensions = OrderedDict()
        for i, (key, value) in enumerate(original_json.items()):
            try:
                value = json.loads(value)
                for j, (k, v) in enumerate(value.items()):
                    if k.endswith('Extension'):  # find the key that is an extension
                        extensions[k] = v
            except ValueError:
                pass
        return extensions
