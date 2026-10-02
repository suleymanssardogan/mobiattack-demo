"""Optional bounded source provenance adapter, never a general symbolic evaluator.

Only exact static/private/final calls are expanded. No branch merging, heap, runtime
configuration, reflection or dynamic dispatch. Existing direct rows take precedence.
"""
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import re
from src.okhttp_candidate_extractor import CALL, STRING, _method as okhttp_method
from src.volley_urlconnection_extractor import _method as connection_method
from src.ktor_candidate_extractor import _method as ktor_method
from src.android_identity import canonical_candidates

MAX_DEPTH=3
MAX_FILES=30000
MAX_BYTES=256_000_000
MAX_METHODS=50000
MAX_EXPANDED_LINES=4096
MAX_EVALUATIONS=2048
MAX_DIAGNOSTICS=512
NETWORK=('Lokhttp3/', 'Lcom/android/volley/', 'Ljava/net/URL;', 'Ljava/net/HttpURLConnection;', 'Ljavax/net/ssl/HttpsURLConnection;', 'Lio/ktor/client/request/', 'Lio/ktor/client/statement/HttpStatement;', 'Lio/ktor/http/HttpMethod$Companion;', 'Lio/ktor/http/URLUtilsKt;')
REGISTER=re.compile(r'(?<![\w/])([vp]\d+)(?![\w/])')
PARAM=re.compile(r'\[*L[^;]+;|\[*[ZBCSIFJD]')

@dataclass
class Method:
    key:str
    source:str
    owner:str
    symbol:str
    flags:set
    lines:list
    locals:int | None
    declaration:int

class Stop(Exception):pass


def call(line):
    if m:=CALL.fullmatch(line):
        mode, names, owner, symbol=m.groups()
        regs=[r.strip() for r in names.split(',') if r.strip()]
        if all(re.fullmatch('[vp]\\d+',r) for r in regs):return mode,regs,owner+'->'+symbol
    if m:=re.fullmatch(r'invoke-(static|direct|virtual|interface)/range\s+\{([vp])(\d+)\s+\.\.\s+([vp])(\d+)\},\s*(L[^;]+;)->(\S+)',line):
        if m[2]==m[4] and 0<=int(m[5])-int(m[3])<=8:
            return m[1],[m[2]+str(i) for i in range(int(m[3]),int(m[5])+1)],m[6]+'->'+m[7]
    return None


def extract_bounded_candidates(root):
    root=Path(root)
    methods,duplicates,fields,mutated,skips={},set(),{},set(),[]
    used=0
    for index,path in enumerate(sorted(root.rglob('*.smali'))):
        source=path.relative_to(root).as_posix()
        if index>=MAX_FILES:
            skips.append(dict(source_file=source,reason='INDEX_FILE_LIMIT'));break
        try:
            size=path.stat().st_size
            if path.is_symlink() or size>2_000_000 or used+size>MAX_BYTES:
                skips.append(dict(source_file=source,reason='INDEX_SOURCE_BOUNDARY'));continue
            used+=size;text=path.read_text()
            if '\x00' in text:raise ValueError()
        except (OSError,ValueError,UnicodeError):
            skips.append(dict(source_file=source,reason='UNREADABLE_SOURCE'));continue
        owner,final,current=None,False,None
        for number,raw in enumerate(text.splitlines(),1):
            line=raw.strip()
            if line.startswith('.class '):owner=line.split()[-1];final='final' in line.split()
            if m:=re.fullmatch(r'\.field (.+) (\S+):Ljava/lang/String; = "([^"\\]*)"',line):
                key=(owner or '')+'->'+m[2]+':Ljava/lang/String;'
                if 'static' in m[1].split() and 'final' in m[1].split():
                    if key in fields:fields[key]=None
                    else:fields[key]=(m[3],dict(source_file=source,source_method=None,line=number,kind='static_final_field'))
            if m:=re.match(r'sput-object [vp]\d+, (L[^;]+;->\S+)',line):mutated.add(m[1])
            if line.startswith('.method ') and owner:
                flags=set(line.split()[1:-1]);symbol=line.split()[-1]
                if final:flags.add('final')
                current=Method(owner+'->'+symbol,source,owner,symbol,flags,[],None,number) if re.fullmatch(r'[^()\s]+\([^)]*\)(?:\[*L[^;]+;|\[*[VZBCSIFJD])',symbol) else None
            elif line=='.end method' and current:
                if current.key in methods:duplicates.add(current.key)
                elif len(methods)<MAX_METHODS:methods[current.key]=current
                else:
                    if not skips or skips[-1]['reason']!='INDEX_METHOD_LIMIT':skips.append(dict(source_file=source,reason='INDEX_METHOD_LIMIT'))
                current=None
            elif current:
                if m:=re.fullmatch(r'\.locals (\d+)',line):current.locals=int(m[1])
                if m:=re.fullmatch(r'\.registers (\d+)',line):
                    types=PARAM.findall(current.symbol.split('(',1)[1].split(')',1)[0])
                    width=sum(2 if t in {'J','D'} else 1 for t in types)+(0 if 'static' in current.flags else 1)
                    current.locals=int(m[1])-width
                if line and (not line.startswith(('.', '#')) or line.startswith('.catch')):current.lines.append((number,line))
    for key in mutated:fields[key]=None
    callers=Counter(target for method in methods.values() for _,line in method.lines if (info:=call(line)) for target in [info[2]])
    diagnostics=[]
    def gap(method,reason,line=0):
        item=dict(source_file=method.source,source_method=method.symbol,line=line,reason=reason,resolution_state='unresolved')
        if len(diagnostics)<MAX_DIAGNOSTICS and item not in diagnostics:diagnostics.append(item)
    def reachable(method,depth=0,seen=()):
        if method.key in seen or depth>MAX_DEPTH+1:return False
        if any(any(token in s for token in NETWORK) for _,s in method.lines):return True
        return any(info[2] in methods and reachable(methods[info[2]],depth+1,seen+(method.key,)) for _,s in method.lines if (info:=call(s)))
    roots=[m for m in methods.values() if reachable(m)]
    # Resolve only a small explicit slice. Direct Ktor gets evaluated independently.
    roots=sorted(roots,key=lambda m:m.key)
    serial=0
    def expand(method,actuals,depth,stack,strings,events):
        nonlocal serial
        if depth>MAX_DEPTH:raise Stop('DEPTH_LIMIT')
        if method.key in stack:raise Stop('CYCLE_DETECTED')
        if method.key in duplicates:raise Stop('AMBIGUOUS_METHOD_DEFINITION')
        if method.locals is None or method.locals<0:raise Stop('REGISTER_LAYOUT_UNRESOLVED')
        if any(s.startswith(':') or re.match(r'(if-|goto|packed-switch|sparse-switch|\.catch|throw)',s) for _,s in method.lines):raise Stop('BRANCH_DEPENDENT_FLOW')
        serial+=1;prefix=serial*1000
        mapping={}
        def reg(name):
            if name.startswith('v') and int(name[1:])>=method.locals:name='p'+str(int(name[1:])-method.locals)
            if name not in mapping:mapping[name]='v'+str(prefix+len(mapping))
            return mapping[name]
        output=[]
        def append(text,number,kind='instruction',origin=None):
            event=origin or dict(source_file=method.source,source_method=method.symbol,source_component=method.owner,line=number,kind=kind)
            output.append((text,event))
            if kind!='instruction':events.append(event)
            if len(events)>512:raise Stop('TRACE_LIMIT')
            if len(output)>MAX_EXPANDED_LINES:raise Stop('EXPANSION_LIMIT')
        types=PARAM.findall(method.symbol.split('(',1)[1].split(')',1)[0])
        if any(t in {'J','D'} for t in types):raise Stop('WIDE_PARAMETER_UNSUPPORTED')
        expected=len(types)+(0 if 'static' in method.flags else 1)
        if actuals is not None:
            if len(actuals)!=expected:raise Stop('ARGUMENT_MAPPING_UNRESOLVED')
            for i,actual in enumerate(actuals):
                parameter_types=types if 'static' in method.flags else [method.owner]+types
                opcode='move-object' if parameter_types[i].startswith(('L','[')) else 'move'
                dest=reg('p'+str(i));append(opcode+' '+dest+', '+actual,method.declaration,'parameter_binding')
                if actual in strings:strings[dest]=strings[actual]
        returned=None;pending=None;changed=False
        for number,line in method.lines:
            # Preserve literal text, rename only operand registers (never URL text).
            if m:=STRING.fullmatch(line):
                dest=reg(m[1]);strings[dest]=m[2]
                append('const-string '+dest+', "'+m[2]+'"',number,'literal_origin');pending=None;continue
            renamed=REGISTER.sub(lambda m:reg(m[1]),line)
            if m:=re.fullmatch(r'move-result-object ([vp]\d+)',renamed):
                dest=m[1]
                if pending is not None:
                    append('move-object '+dest+', '+pending,number,'return_binding')
                    if pending in strings:strings[dest]=strings[pending]
                    else:strings.pop(dest,None)
                else:append(renamed,number);strings.pop(dest,None)
                pending=None;continue
            pending=None
            if m:=re.fullmatch(r'return-object ([vp]\d+)',renamed):
                events.append(dict(source_file=method.source,source_method=method.symbol,line=number,kind='helper_return'))
                returned=m[1];break
            if renamed=='return-void':break
            if renamed.startswith('return'):raise Stop('UNSUPPORTED_RETURN_TYPE')
            if m:=re.fullmatch(r'sget-object ([vp]\d+), (L[^;]+;->\S+:Ljava/lang/String;)',renamed):
                value=fields.get(m[2])
                if value is None:raise Stop('MUTABLE_OR_UNPROVEN_FIELD')
                strings[m[1]]=value[0];append('const-string '+m[1]+', "'+value[0]+'"',number,'field_binding')
                events.append(value[1]);changed=True;continue
            if renamed.startswith(('iget','iput','sput','aget','aput')):raise Stop('MUTABLE_FIELD_OR_COLLECTION_FLOW')
            if m:=re.fullmatch(r'new-instance ([vp]\d+), Ljava/lang/StringBuilder;',renamed):
                strings[m[1]]=[None];append(renamed,number);continue
            info=call(renamed)
            if info:
                mode,names,target=info;owner,symbol=target.split('->',1)
                if owner=='Ljava/lang/StringBuilder;' and names and isinstance(strings.get(names[0]),list):
                    buffer=strings[names[0]]
                    if mode=='direct' and symbol=='<init>()V' and len(names)==1 and buffer[0] is None:
                        buffer[0]='';append(renamed,number,'concat_init');continue
                    if mode=='direct' and symbol=='<init>(Ljava/lang/String;)V' and len(names)==2 and buffer[0] is None and type(strings.get(names[1])) is str:
                        buffer[0]=strings[names[1]];append(renamed,number,'concat_init');continue
                    if mode=='virtual' and symbol=='append(Ljava/lang/String;)Ljava/lang/StringBuilder;' and len(names)==2 and type(buffer[0]) is str and type(strings.get(names[1])) is str:
                        buffer[0]+=strings[names[1]]
                        if len(buffer[0])>8192:raise Stop('CONCAT_LIMIT')
                        append(renamed,number,'literal_concat');pending=names[0];continue
                    if mode=='virtual' and symbol=='toString()Ljava/lang/String;' and len(names)==1 and type(buffer[0]) is str:
                        dest=reg('concat'+str(number));strings[dest]=buffer[0]
                        append('const-string '+dest+', "'+buffer[0]+'"',number,'literal_concat');pending=dest;changed=True;continue
                    raise Stop('CONCAT_VALUE_UNRESOLVED')
                if owner=='Ljava/lang/String;' and mode=='virtual' and symbol=='concat(Ljava/lang/String;)Ljava/lang/String;' and len(names)==2:
                    if not all(type(strings.get(r)) is str for r in names):raise Stop('CONCAT_VALUE_UNRESOLVED')
                    value=strings[names[0]]+strings[names[1]]
                    if len(value)>8192 or '"' in value or '\\' in value:raise Stop('CONCAT_LIMIT')
                    dest=reg('concat'+str(number));strings[dest]=value;append('const-string '+dest+', "'+value+'"',number,'literal_concat');pending=dest;changed=True;continue
                if any(owner.startswith(token) for token in NETWORK):
                    append('invoke-'+mode+' {'+', '.join(names)+'}, '+target,number);continue
                if target in methods and not symbol.startswith('<'):
                    callee=methods[target]
                    if target in stack+(method.key,):raise Stop('CYCLE_DETECTED')
                    if mode=='static' and 'static' not in callee.flags or mode=='direct' and 'private' not in callee.flags or mode=='virtual' and 'static' in callee.flags:
                        raise Stop('DISPATCH_UNRESOLVED')
                    if mode not in {'static','direct'} and not (mode=='virtual' and 'final' in callee.flags):raise Stop('DISPATCH_UNRESOLVED')
                    if callers[target]!=1:raise Stop('AMBIGUOUS_CALLERS')
                    events.append(dict(source_file=method.source,source_method=method.symbol,line=number,kind='helper_call',callee=target))
                    sub,returned_register,_=expand(callee,names,depth+1,stack+(method.key,),strings,events)
                    output.extend(sub)
                    if len(output)>MAX_EXPANDED_LINES:raise Stop('EXPANSION_LIMIT')
                    pending=returned_register;changed=True;continue
                # Unknown returns/configuration/reflection cannot provide provenance.
                if not symbol.startswith('<init>') or owner.startswith(('Ljava/lang/reflect/','Ljava/util/')):raise Stop('UNKNOWN_METHOD_OR_RUNTIME_CONFIGURATION')
                append(renamed,number);continue
            if renamed.startswith('invoke-'):raise Stop('UNSUPPORTED_INVOKE_FORM')
            if m:=re.fullmatch(r'move-object(?:/from16|/16)? ([vp]\d+), ([vp]\d+)',renamed):
                if m[2] in strings:strings[m[1]]=strings[m[2]]
                else:strings.pop(m[1],None)
            elif m:=re.match(r'^[a-z][\w/-]*\s+([vp]\d+)(?:,|$)',renamed):strings.pop(m[1],None)
            append(renamed,number)
        return output,returned,changed
    rows,ktor_gaps=[],[]
    for method in roots:
        # Direct Ktor is independent of resolver availability/limits.
        if method.locals is None or method.locals<0:
            gap(method,'REGISTER_LAYOUT_UNRESOLVED');continue
        original=[]
        for number,line in method.lines:
            if not STRING.fullmatch(line):
                line=REGISTER.sub(lambda m:'p'+str(int(m[1][1:])-method.locals) if m[1].startswith('v') and int(m[1][1:])>=method.locals else m[1],line)
            info=call(line)
            if info:line='invoke-'+info[0]+' {'+', '.join(info[1])+'}, '+info[2]
            original.append((number,line))
        direct,gaps=ktor_method(original,method.source,method.owner,method.symbol)
        rows.extend(direct);ktor_gaps.extend(gaps[:512-len(ktor_gaps)])
    for index,method in enumerate(roots):
        if skips:
            gap(method,'INCOMPLETE_INDEX');continue
        if index>=MAX_EVALUATIONS:
            gap(method,'EVALUATION_LIMIT');break
        events=[]
        try:
            expanded,_,changed=expand(method,None,0,(),{},events)
            if not changed:continue
        except Stop as error:
            gap(method,str(error));continue
        lines=[(i+1,s) for i,(s,event) in enumerate(expanded)]
        origin={i+1:event for i,(s,event) in enumerate(expanded)}
        found=[]
        for parser in (okhttp_method,connection_method,ktor_method):
            candidates,_=parser(lines,method.source,method.owner,method.symbol);found.extend(candidates)
        for row in found:
            request=origin[row['request_line']]
            row.update(source_file=request['source_file'],source_component=request['source_component'],request_line=request['line'])
            evidence=row['evidence'];trace=list(events)
            def remap(obj):
                if isinstance(obj,list):return [remap(v) for v in obj]
                if not isinstance(obj,dict):return obj
                result={}
                for key,value in obj.items():
                    if (key.endswith('_line') or key=='line') and type(value) is int and value in origin:
                        event=origin[value];result[key]=event['line'];trace.append(dict(event,kind='resolved_'+key))
                    else:result[key]=remap(value)
                return result
            evidence=remap(evidence)
            evidence['source_method']=request['source_method']
            evidence['bounded_provenance']=sorted({repr(e):e for e in trace}.values(),key=lambda e:(e['source_file'],e.get('line',0),e['kind']))
            evidence['resolver_max_depth']=MAX_DEPTH
            row['evidence']=evidence;rows.append(row)
    rows=canonical_candidates(rows)
    unique={}
    for row in rows:unique.setdefault(row['candidate_id'],row)
    return dict(api_candidates=list(unique.values()),discovery_diagnostics={
        'ktor':dict(unresolved=ktor_gaps,coverage=dict(partial=bool(ktor_gaps or skips),skipped=skips)),
        'bounded_provenance':dict(unresolved=diagnostics,coverage=dict(partial=bool(diagnostics or skips),skipped=skips),max_depth=MAX_DEPTH)})
