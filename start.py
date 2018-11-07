import os
import sys
import inspect

snippet = '''
# paste these codes into your exp.py
# https://github.com/matrix1001/welpwn # reserve this link :)
import sys
sys.path.insert(0,'{dir}')
from PwnContext.core import *
'''

if __name__ == '__main__':
    currentdir = os.path.dirname(
        os.path.abspath(inspect.getfile(inspect.currentframe()))
        )
    print(snippet.format(dir=currentdir))
