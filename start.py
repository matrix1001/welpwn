import os,sys,inspect


snippet = '''
import sys
sys.path.insert(0,'{dir}') 
from PwnContext.core import *
'''

if __name__ == '__main__':
    currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
    print('paste following code into your exp.py')
    print(snippet.format(dir=currentdir))
