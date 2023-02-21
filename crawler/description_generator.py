from sumy.nlp.tokenizers import Tokenizer
from sumy.parsers.plaintext import PlaintextParser
from sumy.summarizers.lex_rank import LexRankSummarizer
from sanitiser import sanitise_and_limit


FALLBACK_DESC_MAX_WORDS = 25
MAX_DESC_LENGTH = 200
FALLBACK_LENGTH = 15000
SENTENCE_COUNT = 2


def _generate_fallback_description(text):
    words = text.split()

    description = ' '.join(words[:FALLBACK_DESC_MAX_WORDS])

    description = sanitise_description(description)

    return description


def sanitise_description(description):
    return sanitise_and_limit(description, MAX_DESC_LENGTH)


def generate_description(text):
    if len(text) > FALLBACK_LENGTH:
        fallback_description = _generate_fallback_description(text)
        return fallback_description

    parser = PlaintextParser.from_string(text, Tokenizer('english'))

    summarizer = LexRankSummarizer()
    summary = summarizer(parser.document, sentences_count=SENTENCE_COUNT)
    description_snippet = ' '.join([str(s) for s in summary])

    description_snippet = sanitise_description(description_snippet)

    return description_snippet
