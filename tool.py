#!/usr/bin/env python3
"""Inspect a script header under an explicit Unix shebang policy; never execute it."""
import os
import re
import shlex
from _support import InputError, Parser, Report, anchored, cli, guarded, limits, positive
TOOL='shebang-portability-audit'
BASELINE=('/bin/sh','/usr/bin/env')

@guarded(TOOL)
def audit(path, *, allow_env_s=False,allow_interpreter=(),require_executable=False,max_header_bytes=4096,max_portable_bytes=127,max_findings=1000):
    limits(max_header_bytes=max_header_bytes,max_portable_bytes=max_portable_bytes,max_findings=max_findings)
    if isinstance(allow_interpreter,str) or any(not isinstance(p,str) or not p.startswith('/') for p in allow_interpreter):
        raise InputError('allowed interpreters must be an iterable of absolute paths')
    with anchored(path) as fd:
        data=os.read(fd,max_header_bytes+1);mode=os.fstat(fd).st_mode
    line=data.split(b'\n',1)[0]
    if len(line)>max_header_bytes:raise InputError('shebang header byte limit exceeded')
    report=Report(TOOL,max_findings);summary={'header_bytes':len(line),'executable_bit':bool(mode&0o111)}
    if require_executable and not mode&0o111:report.add('missing_executable_bit')
    if line.startswith(b'\xef\xbb\xbf'):report.add('bom_before_shebang');line=line[3:]
    if not line.startswith(b'#!'):report.add('missing_shebang');return report.finish(summary)
    if line.endswith(b'\r'):report.add('crlf_shebang');line=line[:-1]
    if len(line)>max_portable_bytes:report.add('shebang_length_policy_exceeded')
    if any(b<32 and b!=9 for b in line) or 127 in line:report.add('control_in_shebang');return report.finish(summary)
    try:header=line[2:].decode('ascii').strip(' \t')
    except UnicodeDecodeError:report.add('non_ascii_shebang');return report.finish(summary)
    if not header:report.add('missing_interpreter');return report.finish(summary)
    parts=header.split(None,1);interpreter=parts[0];rest=parts[1] if len(parts)>1 else ''
    if not interpreter.startswith('/'):report.add('relative_interpreter')
    if interpreter not in (*BASELINE,*allow_interpreter):report.add('interpreter_outside_policy')
    if interpreter=='/usr/bin/env':
        summary['kind']='env';split_string=rest.startswith('-S ') or rest.startswith('-S\t')
        summary['env_split_string']=split_string
        if split_string:
            if not allow_env_s:report.add('env_split_string_extension')
            value=rest[2:].lstrip()
            if any(c in value for c in '\\$#'):
                report.add('unsupported_env_split_syntax');return report.finish(summary)
            try:tokens=shlex.split(value,posix=True)
            except ValueError:report.add('malformed_env_quotes');return report.finish(summary)
        else:
            tokens=rest.split()
            if len(tokens)>1:report.add('env_requires_split_string')
            if any(c in rest for c in '\\$#\'"'):report.add('unsupported_env_syntax')
        if not tokens:report.add('missing_env_command')
        elif not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.+\-]*',tokens[0]):report.add('unsupported_env_command_or_options')
        summary['argument_count']=max(0,len(tokens)-1)
    else:
        summary['kind']='direct';summary['argument_count']=len(rest.split())
        if len(rest.split())>1:report.add('multiple_direct_arguments')
        if any(c in rest for c in '\\$#\'"'):report.add('unsupported_direct_argument_syntax')
    return report.finish(summary)

def parse_and_audit():
    p=Parser(description=__doc__);p.add_argument('file');p.add_argument('--allow-env-s',action='store_true');p.add_argument('--allow-interpreter',action='append',default=[]);p.add_argument('--require-executable',action='store_true')
    for name,default in [('max-header-bytes',4096),('max-portable-bytes',127),('max-findings',1000)]:p.add_argument('--'+name,type=positive,default=default)
    a=vars(p.parse_args());path=a.pop('file');return audit(path,**a)
if __name__=='__main__':raise SystemExit(cli(TOOL,parse_and_audit))
