import re


def _remove_repeated_whitespace(text):
    return re.sub(' +', ' ', text)


def sanitise_and_limit(text, max_length):
    if text is None:
        return ''

    text = text.strip()

    text = text.replace('\n', ' ')

    text = _remove_repeated_whitespace(text)

    if len(text) > max_length:
        text = text[:max_length]

        text += '...'

    return text
