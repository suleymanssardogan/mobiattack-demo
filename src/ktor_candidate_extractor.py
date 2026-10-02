"""Ktor V1: exact builder/URL/method flows and default-block String calls.

Unresolved lambdas and coroutine control flow are not interpreted.
"""
from dataclasses import dataclass
import re
from src.okhttp_candidate_extractor import CALL, STRING, MOVE, NEW, RESULT, Literal, _identity

CLIENT='Lio/ktor/client/HttpClient;'
BUILDER='Lio/ktor/client/request/HttpRequestBuilder;'
URL_BUILDER='Lio/ktor/http/URLBuilder;'
HTTP_METHOD='Lio/ktor/http/HttpMethod;'
COMPANION='Lio/ktor/http/HttpMethod$Companion;'
FACADE={'Lio/ktor/client/request/BuildersKt;', 'Lio/ktor/client/request/BuildersKt__BuildersKt;'}
CONT='Lkotlin/coroutines/Continuation;'
VERBS={'get':'GET','post':'POST','put':'PUT','patch':'PATCH','delete':'DELETE','head':'HEAD','options':'OPTIONS'}

@dataclass
class Request:
    allocation: int
    initialized: bool=False
    valid: bool=True
    url: Literal | None=None
    url_call: int | None=None
    method: Literal | None=None
    method_call: int | None=None

@dataclass
class UrlReceiver:
    request: Request


def _method(lines,source,component,symbol):
    rows,gaps=[],[]
    def gap(reason,line):
        gaps.append(dict(source_file=source,source_component=component,source_method=symbol,line=line,reason=reason,resolution_state='unresolved'))
    if not any('Lio/ktor/' in s for _,s in lines):return rows,gaps
    if not component or len(lines)>4096 or any(s.startswith(':') or re.match(r'(if-|goto|packed-switch|sparse-switch|\.catch)',s) for _,s in lines):
        gap('UNSUPPORTED_CONTROL_FLOW_OR_SOURCE',lines[0][0] if lines else 0)
        return rows,gaps
    regs,pending={},None
    def emit(request,line,origin):
        identity=_identity(request.url.value) if request.url else None
        if not request.initialized or not request.valid or not identity or not request.method:
            gap('KTOR_URL_OR_METHOD_UNRESOLVED',line);return
        rows.append(dict(identity,framework='ktor',method=request.method.value,source_file=source,source_component=component,
            request_line=line,status='static_api_candidate',resolution_state='resolved',evidence=dict(source_method=symbol,
            allocation_line=request.allocation,url_literal_line=request.url.line,url_call_line=request.url_call,
            method_line=request.method.line,method_call_line=request.method_call,request_call_line=line,
            method_origin=origin,dispatch_observed=False,query_values_removed=bool(identity['query_keys']))))
    for number,line in lines:
        if not line or line.startswith(('.', '#')):continue
        if m:=RESULT.fullmatch(line):
            regs.pop(m[1],None)
            if pending is not None:regs[m[1]]=pending
            pending=None;continue
        pending=None
        if line.startswith(('return','throw')):break
        if m:=STRING.fullmatch(line):regs[m[1]]=Literal(m[2],number);continue
        if m:=re.fullmatch(r'const(?:/4|/16)? ([vp]\d+), (0x[0-9a-fA-F]+|\d+)',line):regs[m[1]]=int(m[2],0);continue
        if m:=MOVE.fullmatch(line):
            value=regs.get(m[2]);regs.pop(m[1],None)
            if value is not None:regs[m[1]]=value
            continue
        if m:=NEW.fullmatch(line):
            regs.pop(m[1],None)
            if m[2]==BUILDER:regs[m[1]]=Request(number)
            continue
        if m:=re.fullmatch(r'sget-object ([vp]\d+), Lio/ktor/http/HttpMethod;->Companion:'+re.escape(COMPANION),line):regs[m[1]]='method_companion';continue
        m=CALL.fullmatch(line)
        if m:
            mode,text,owner,sig=m.groups(); names=[r.strip() for r in text.split(',') if r.strip()]
            args=[regs.get(r) for r in names];recv=args[0] if args else None
            if owner==BUILDER and isinstance(recv,Request):
                if mode=='direct' and sig=='<init>()V' and len(args)==1 and not recv.initialized:recv.initialized=True;continue
                if mode=='virtual' and recv.initialized and recv.valid:
                    if sig=='getUrl()'+URL_BUILDER and len(args)==1:pending=UrlReceiver(recv);continue
                    if sig=='setMethod('+HTTP_METHOD+')V' and len(args)==2:
                        recv.method=args[1] if isinstance(args[1],Literal) and args[1].value in VERBS.values() else None
                        recv.method_call=number;continue
                recv.valid=False;gap('UNSUPPORTED_KTOR_BUILDER_OPERATION',number);continue
            if owner==COMPANION and mode=='virtual' and recv=='method_companion' and len(args)==1:
                verb=next((v for k,v in VERBS.items() if sig=='get'+k.capitalize()+'()'+HTTP_METHOD),None)
                if verb:pending=Literal(verb,number)
                continue
            if owner=='Lio/ktor/client/request/HttpRequestKt;' and mode=='static' and sig=='url('+BUILDER+'Ljava/lang/String;)V' and len(args)==2 and isinstance(recv,Request):
                recv.url=args[1] if isinstance(args[1],Literal) else None;recv.url_call=number;continue
            if owner=='Lio/ktor/http/URLUtilsKt;' and mode=='static' and sig=='takeFrom('+URL_BUILDER+'Ljava/lang/String;)'+URL_BUILDER and len(args)==2 and isinstance(recv,UrlReceiver):
                recv.request.url=args[1] if isinstance(args[1],Literal) else None;recv.request.url_call=number;pending=recv;continue
            if owner in FACADE and mode=='static':
                name=sig.split('(')[0]
                direct=name.removesuffix('$default')
                if direct in VERBS and sig==direct+'$default('+CLIENT+'Ljava/lang/String;Lkotlin/jvm/functions/Function1;'+CONT+'ILjava/lang/Object;)Ljava/lang/Object;' and len(args)==6:
                    # Only default URL block; default URL or unknown overriding lambda is forbidden.
                    if type(args[4]) is int and args[4]&2 and not args[4]&1 and isinstance(args[1],Literal):
                        request=Request(number,True,url=args[1],url_call=number,method=Literal(VERBS[direct],number),method_call=number)
                        emit(request,number,'verb_default_block')
                    else:gap('KTOR_DSL_UNRESOLVED',number)
                    continue
                if (name in VERBS or name=='request') and sig==name+'('+CLIENT+BUILDER+CONT+')Ljava/lang/Object;' and len(args)==3 and isinstance(args[1],Request):
                    request=args[1]
                    if name in VERBS:request.method=Literal(VERBS[name],number);request.method_call=number
                    emit(request,number,'explicit_verb' if name in VERBS else 'explicit_builder_method');continue
            if owner=='Lio/ktor/client/statement/HttpStatement;' and mode=='direct' and sig=='<init>('+BUILDER+CLIENT+')V' and len(args)==3 and isinstance(args[1],Request):
                emit(args[1],number,'explicit_builder_method');continue
            for value in args:
                if isinstance(value,Request):value.valid=False
                elif isinstance(value,UrlReceiver):value.request.valid=False
            if owner.startswith('Lio/ktor/'):gap('KTOR_DSL_OR_RECEIVER_UNRESOLVED',number)
            continue
        if line.startswith(('invoke-','iput','sput','aput','monitor-')):
            for value in regs.values():
                if isinstance(value,Request):value.valid=False
                elif isinstance(value,UrlReceiver):value.request.valid=False
            gap('UNSUPPORTED_KTOR_FLOW',number);continue
        if m:=re.match(r'^[a-z][\w/-]*\s+([vp]\d+)(?:,|$)',line):regs.pop(m[1],None)
    return rows,gaps
