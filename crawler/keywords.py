import nltk
import yake
from text import lemmatise_tokens
from gensim import corpora, models
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import string
from nltk.tokenize.treebank import TreebankWordDetokenizer


MAX_NGRAM_SIZE = 3
DEDUPLICATION_THRESHOLD = 0.9
KEYWORD_NUM = 40
ANALYSIS_CUTOFF = 10000


nltk.download('wordnet')


# nltk.download('stopwords')
# nltk.download('punkt')
# nltk.download('wordnet')
#
# 
# def get_keywords(text):
#     text = text.translate(str.maketrans('', '', string.punctuation))
# 
#     stop_words = set(stopwords.words('english'))
#     tokens = word_tokenize(text)
#     clean_tokens = [token.lower() for token in tokens if
#                     not token.lower() in stop_words and token.lower() not in string.punctuation]
# 
#     dictionary = corpora.Dictionary([clean_tokens])
#     bow = dictionary.doc2bow(clean_tokens)
#     lsa_model = models.LsiModel([bow], id2word=dictionary, num_topics=5)
#     lsa_keywords = lsa_model.show_topic(0, topn=len(clean_tokens))
#     lsa_keywords = [keyword[0] for keyword in lsa_keywords]
# 
#     lemmer = nltk.WordNetLemmatizer()
#     lemmed_keywords = [lemmer.lemmatize(token) for token in clean_tokens]
#     all_keywords = set(lsa_keywords + lemmed_keywords)
# 
#     result = ','.join(all_keywords)
# 
#     return result


def get_keywords(text):
    text = text[:ANALYSIS_CUTOFF]

    extractor = yake.KeywordExtractor(lan='en', n=MAX_NGRAM_SIZE, dedupLim=DEDUPLICATION_THRESHOLD,
                                      top=KEYWORD_NUM, features=None)

    result = extractor.extract_keywords(text.lower())

    keywords = []
    for item in result:
        if item[0].strip() != '':
            keywords.append(lemmatise_tokens(item[0]))

    return ','.join(keywords)
