import zlib
import json
import argparse
from io import BytesIO
from enum import IntEnum

class RefKind(IntEnum):
    Unkown = 0
    Declaration = 1 << 0
    Definition = 1 << 1
    Reference = 1 << 2
    Spelled = 1 << 3
    All = Declaration | Definition | Reference | Spelled
    
class SymbolKind(IntEnum):
    File = 1
    Module = 2
    Namespace = 3
    Package = 4
    Class = 5
    Method = 6
    Property = 7
    Field = 8
    Constructor = 9
    Enum = 10
    Interface = 11
    Function = 12
    Variable = 13
    Constant = 14
    String = 15
    Number = 16
    Boolean = 17
    Array = 18
    Object = 19
    Key = 20
    Null = 21
    EnumMember = 22
    Struct = 23
    Event = 24
    Operator = 25
    TypeParameter = 26

class SymbolLanguage(IntEnum):
    C = 0
    Cpp = 1
    ObjC = 2
    Swift = 3
    
class ClangIndex:
    def __init__(self, index_path):
        self.index_path = index_path
        self.cindex = self.parse_riff_file()
        
    def consume_id(self, stream):
        return stream.read(8).hex()
    
    def consume8(self, stream):
        return int.from_bytes(stream.read(1), byteorder='little')
    
    def consume_var(self, stream):
        more = 1 << 7
        b = self.consume8(stream)
        if not (b & more):
            return b
        val = b & ~more
        shift = 7
        while (b & more) and shift < 32:
            b = self.consume8(stream)
            val |= (b & ~more) << shift
            shift += 7
        return val
    
    def consume_string(self, stream):
        idx = self.consume_var(stream)
        return self.string_table[idx]
    
    def read_location(self, stream):
        location = {}
        file_uri = self.consume_string(stream)
        start = {"line": self.consume_var(stream), "column": self.consume_var(stream)}
        end = {"line": self.consume_var(stream), "column": self.consume_var(stream)}
        location["file_uri"] = file_uri
        location["start"] = start
        location["end"] = end
        return location
    
    def read_symbol(self, stream):
        symbol = {}
        id = self.consume_id(stream)
        kind = SymbolKind(self.consume8(stream))
        lang = SymbolLanguage(self.consume8(stream))
        name = self.consume_string(stream)
        scope = self.consume_string(stream)
        template_specialization_args = self.consume_string(stream)
        definition = self.read_location(stream)
        canonical_declaration = self.read_location(stream)
        references = self.consume_var(stream)
        flags = self.consume8(stream)
        signature = self.consume_string(stream)
        completion_snippet_suffix = self.consume_string(stream)
        documentation = self.consume_string(stream)
        return_type = self.consume_string(stream)
        sym_type = self.consume_string(stream)
        include_headers_size = self.consume_var(stream)
        include_headers = []
        for _ in range(include_headers_size):
            include_header = self.consume_string(stream)
            refs_with_directives = self.consume_var(stream)
            include_header_references = refs_with_directives >> 2
            supported_directives = refs_with_directives & 0b11
            include_headers.append({"header": include_header, "references": include_header_references, "supported_directives": supported_directives})
        symbol["id"] = id
        symbol["kind"] = kind
        symbol["lang"] = lang
        symbol["name"] = name
        symbol["scope"] = scope
        symbol["template_specialization_args"] = template_specialization_args
        symbol["definition"] = definition
        symbol["canonical_declaration"] = canonical_declaration
        symbol["references"] = references
        symbol["flags"] = flags
        symbol["signature"] = signature
        symbol["completion_snippet_suffix"] = completion_snippet_suffix
        symbol["documentation"] = documentation
        symbol["return_type"] = return_type
        symbol["type"] = sym_type
        symbol["include_headers"] = include_headers
        return symbol
        
    def parse_chunk(self, file):
        chunk_id = file.read(4)
        chunk_size = int.from_bytes(file.read(4), byteorder='little')
        return chunk_id, chunk_size
    
    def parse_varint(self, data):
        result = 0
        shift = 0
        for b in data:
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return result, shift // 7 + 1
    
    def parse_meta(self, data):
        version = int.from_bytes(data, byteorder='little')
        self.version = version
        return version
    
    def parse_stri(self, data):
        uncompressed_size = int.from_bytes(data[:4], byteorder='little')
        compressed_data = data[4:]
        uncompressed_data = zlib.decompress(compressed_data, bufsize=uncompressed_size)
        string_table = uncompressed_data.decode().split('\0')
        self.string_table = string_table
        return string_table
    
    def parse_symb(self, data):
        stream = BytesIO(data)
        symbols =  []
        while stream.tell() < len(data):
            symbol = self.read_symbol(stream)
            symbols.append(symbol)
        self.symbols = symbols
        return symbols
        
    def parse_refs(self, data):
        stream = BytesIO(data)
        refs = []
        while stream.tell() < len(data):
            ref = {}
            symbol_id = self.consume_id(stream)
            num_refs = self.consume_var(stream)
            references = []
            for _ in range(num_refs):
                reference = {}
                kind = self.consume8(stream)
                location = self.read_location(stream)
                container = self.consume_id(stream)
                reference["kind"] = kind
                reference["location"] = location
                reference["container"] = container
                references.append(reference)
            ref["symbol_id"] = symbol_id
            ref["references"] = references
            refs.append(ref)
        self.refs = refs
        return refs
        
    def parse_rela(self, data):
        stream = BytesIO(data)
        relations = []
        while stream.tell() < len(data):
            relation = {}
            subject = self.consume8(stream)
            predicate = self.consume8(stream)
            object = self.consume8(stream)
            relation["subject"] = subject
            relation["predicate"] = predicate
            relation["object"] = object
            relations.append(relation)
        self.relations = relations
        return relations
        
    def parse_srcs(self, data):
        stream = BytesIO(data)
        sources = []
        while stream.tell() < len(data):
            src = {}
            flags = int.from_bytes(stream.read(1), 'little')
            src['flags'] = flags
            uri = self.consume_string(stream)
            digest = stream.read(8)
            direct_include_size = self.consume_var(stream)
            direct_includes = []
            for _ in range(direct_include_size):
                inc = self.consume_string(stream)
                direct_includes.append(inc)
            src['uri'] = uri
            src['digest'] = digest
            src['direct_includes'] = direct_includes
            sources.append(src)
        self.sources = sources
        return sources
        
    def parse_cmdl(self, data):
        cmd_reader = BytesIO(data)
        commands = []
        while cmd_reader.tell() < len(data):
            command = {}
            directory = self.consume_string(cmd_reader)
            num_commands = self.consume_var(cmd_reader)
            command["directory"] = directory
            command["commands"] = []
            for _ in range(num_commands):
                cmd = self.consume_string(cmd_reader)
                command["commands"].append(cmd)
            commands.append(command)
        self.commands = commands
        return commands

    def parse_data(self, id, data):
        # print(f"Parsing: {id}")
        match id:
            case "meta":
                return self.parse_meta(data)
            case "stri":
                return self.parse_stri(data)
            case "symb":
                return self.parse_symb(data)
            case "refs":
                return self.parse_refs(data)
            case "rela":
                return self.parse_rela(data)
            case "srcs":
                return self.parse_srcs(data)
            case "cmdl":
                return self.parse_cmdl(data)
            case _:
                raise ValueError(f"Unknown chunk ID: {id}")

    def parse_riff_file(self):
        cindex = {}
        with open(self.index_path, 'rb') as file:
            riff_id = file.read(4)
            # print(f"RIFF ID: {riff_id.decode()}")
            riff_size = int.from_bytes(file.read(4), byteorder='little')
            format_id = file.read(4)
            # print(f"Format ID: {format_id.decode()}")

            while file.tell() < riff_size:
                chunk_id, chunk_size = self.parse_chunk(file)
                # Process chunk data here
                chunk_data = file.read(chunk_size)
                # riff_chunks[chunk_id] = chunk_data
                cindex[chunk_id.decode()] = self.parse_data(chunk_id.decode(), chunk_data)
                # Example: Print chunk ID and size
                # print(f"Chunk ID: {chunk_id.decode()}, Chunk Size: {chunk_size}")
                # print(cindex[chunk_id.decode()])
                # print(json.dumps(cindex[chunk_id.decode()], indent=4))
        return cindex
    
    def __repr__(self) -> str:
        return f"ClangIndex({self.index_path})\n{json.dumps(self.cindex, indent=4)}"

def parse_args():
    parser = argparse.ArgumentParser(description="Parse RIFF file")
    parser.add_argument("index_path", type=str, help="Path to RIFF file")
    parser.add_argument("--output", type=str, help="Output file")
    return parser.parse_args()

def main():
    args = parse_args()
    cindex = ClangIndex(args.index_path)
    if args.output is not None:
        with open(args.output, 'w') as f:
            json.dump(cindex.cindex, f, indent=4)
    else:
        print(json.dumps(cindex.cindex, indent=4))
        
if __name__ == "__main__":
    main()
