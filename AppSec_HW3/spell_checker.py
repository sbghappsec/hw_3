from __future__ import print_function
import enchant
from pprint import pprint

#import dictionary
d = enchant.Dict('en_US')

def getSuggestions(word):
    suggestions = d.suggest(word)
    if len(suggestions) == 0:
        return 'no suggestions'
    suggestions = ', '.join(suggestions)
    return suggestions

def spellchecker(filename):
    try:
        with open(filename, 'r') as text_file:
            error_count = 0
            errors_suggestions = {}
            f = text_file.read()
            for word in f.split(): 
                stripped_word = word.strip(":;-,!_?)(&*$#)./'\"")
                if stripped_word == '': 
                    pass
                elif not d.check(stripped_word):
                    error_count += 1
                    errors_suggestions[stripped_word] = getSuggestions(stripped_word)
                else:
                    pass
            return errors_suggestions
    except FileNotFoundError:
        return None