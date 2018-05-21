from PwnContext import *
from pwnlib.context import _validator, _Tls_DictStack, _defaultdict
from c_utils import *
class Symbol(object):
    def __init__(self, name, addr, loc = 'base', typ = 'raw', size = 0, ptr_array = False, struct_name = ''):
        self.name = name
        self.addr = addr
        self.loc = loc
        self.type = typ
        self.size = size
        self.ptr_array = ptr_array
        if struct_name == '':
            if context.bytes == 4:self.struct_name = 'long'
            elif context.bytes == 8:self.struct_name = 'long long'
        else: self.struct_name = struct_name
        
    def __repr__(self):
        return 'Symbol({}, {}, {}, {})'.format(self.name, hex(self.addr), self.loc, hex(self.size))
    @property
    def address(self):
        '''real address'''
        if not ctx.bases or (self.loc == 'base' and not ctx.binary.pie):return self.addr
        else: return ctx.bases[self.loc]+self.addr
    def leak(self, size = 0):
        if size == 0 and self.size != 0 :size = self.size
        else: size = context.bytes
        '''leak data at its address'''
        if self.type == 'raw': return ctx.leak(self.address, size)
        if self.type == 'ptr':
            addr = unpack(ctx.leak(self.address, context.bytes))
            return ctx.leak(addr, size)
        if type(self.type) == int:#array
            ret = []
            addr = self.address
            for i in range(self.type):
                ret.append(ctx.leak(addr+i*size, size))
            return ret
            

class SymbolContext(object):
    defaults = {
                'symbols':None,
               }
    def __init__(self, symbols = {}, structs = {}):
        self._tls = _Tls_DictStack(_defaultdict(SymbolContext.defaults))
        self.symbols = symbols
        self.structs = structs
    def __repr__(self):
        return str(self.symbols)
    def __getitem__(self, n):
        return self.symbols[n]
    
        
    @_validator
    def symbols(self, symbols):
        container = []
        if type(symbols) == dict:
            for name in symbols:
                container.append(Symbol(name, symbols[name]))
        elif type(symbols) == Symbol:
            container.append(symbols)
        elif type(symbols) == list:
            for sym in symbols: container.append(sym)
        return container
    
    def add(self, symbol):
        self.symbols.append(symbol)
        return self.symbols
    def get(self, name):
        for sym in self.symbols:
            if sym.name == name:
                return sym
        return None       
    def remove(self, name):
        for sym in self.symbols:
            if sym.name == name:
                self.symbols.remove(sym)
                return True
        return False
    @property
    def address(self):
        address = {}
        for sym in self.symbols:
            address[sym.name] = sym.address
        return address
    @property
    def leak(self):
        leak = {}
        for sym in self.symbols:
            leak[sym.name] = sym.leak()
        return leak
    @property
    def gdbscript(self):
        gdbscript = ''
        code = ''
        symbol_file_name = ''
        for name in self.structs:
            code += self.structs[name]
        if code != '':
            for name in self.structs:
                code += 'struct {} _{};\n'.format(name, name)
            symbol_file_name = struct_compile(code)
        if symbol_file_name == '':
            for sym in self.symbols:
                gdbscript += 'set ${}={}\n'.format(sym.name, hex(sym.address))
        else:
            gdbscript += 'symbol-file {}\n'.format(symbol_file_name)
            for sym in self.symbols:
                common_type = ['char', 'byte', 'short', 'int', 'long', 'long long']
                struct = sym.struct_name
                if type(sym.type) == int and sym.ptr_array:
                    struct = struct+' **'
                elif sym.type == 'ptr' or type(sym.type) == int:
                    struct = struct+' **'
                elif sym.type == 'raw':
                    struct = struct+' *'
                if sym.struct_name not in common_type:
                    struct = 'struct {}'.format(struct)
                gdbscript += 'set ${}=({}){}\n'.format(sym.name, struct, hex(sym.address))        

        return gdbscript
 
sym_ctx = SymbolContext() 