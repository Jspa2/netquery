import nltk
import yake
from gensim import corpora, models
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import string
from nltk.tokenize.treebank import TreebankWordDetokenizer


lemmer = nltk.WordNetLemmatizer()


def lemmatise_tokens(text):
    tokens = word_tokenize(text)

    tokens = [lemmer.lemmatize(token) for token in tokens]

    return TreebankWordDetokenizer().detokenize(tokens)
