import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).parent))
spec=importlib.util.spec_from_file_location("audit_tool",Path(__file__).with_name("tool.py"))
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def codes(self,result):return {x["code"] for x in result.get("findings",[])}
    def call(self,*args):
        result=subprocess.run([sys.executable,str(Path(__file__).with_name("tool.py")),*map(str,args)],capture_output=True,text=True)
        return result.returncode,json.loads(result.stdout)
    def test_bad_cli(self):
        code,result=self.call("--unknown");self.assertEqual(code,2);self.assertEqual(result["status"],"error")
    def test_examples(self):
        result=subprocess.run([sys.executable,str(Path(__file__).parent/"examples"/"run_examples.py")],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        reports=[json.loads(x) for x in result.stdout.splitlines()]
        self.assertEqual([r["status"] for r in reports],["pass","findings"])

    def write(self,data):
        p=self.root/'script';p.write_bytes(data);return p
    def test_simple_and_cli(self):
        p=self.write(b'#!/bin/sh\necho not-executed\n');self.assertEqual(tool.audit(p)['status'],'pass');self.assertEqual(self.call(p)[0],0)
    def test_crlf_bom_and_missing(self):
        p=self.write(b'\xef\xbb\xbf#!/bin/sh\r\n');self.assertTrue({'bom_before_shebang','crlf_shebang'}<=self.codes(tool.audit(p)));self.assertEqual(self.call(p)[0],1)
        self.assertIn('missing_shebang',self.codes(tool.audit(self.write(b'echo hi\n'))))
    def test_env_multiple_and_split_opt_in(self):
        p=self.write(b'#!/usr/bin/env python3 -u\n');self.assertIn('env_requires_split_string',self.codes(tool.audit(p)))
        p=self.write(b'#!/usr/bin/env -S python3 -u\n');self.assertIn('env_split_string_extension',self.codes(tool.audit(p)));self.assertEqual(tool.audit(p,allow_env_s=True)['status'],'pass')
    def test_env_quotes_and_unsupported_expansion(self):
        p=self.write(b'#!/usr/bin/env -S python3 "an argument"\n');self.assertEqual(tool.audit(p,allow_env_s=True)['summary']['argument_count'],1)
        p=self.write(b'#!/usr/bin/env -S python3 ${HOME}\n');self.assertIn('unsupported_env_split_syntax',self.codes(tool.audit(p,allow_env_s=True)))
        p=self.write(b'#!/usr/bin/env -S python3 "unterminated\n');self.assertIn('malformed_env_quotes',self.codes(tool.audit(p,allow_env_s=True)))
    def test_interpreter_policy(self):
        p=self.write(b'#!/usr/bin/python3\n');self.assertIn('interpreter_outside_policy',self.codes(tool.audit(p)));self.assertEqual(tool.audit(p,allow_interpreter=['/usr/bin/python3'])['status'],'pass')
        p=self.write(b'#!python3\n');self.assertIn('relative_interpreter',self.codes(tool.audit(p)))
    def test_only_header_read_no_execution(self):
        p=self.write(b'#!/bin/sh\n'+b'\xff'*100000);self.assertEqual(tool.audit(p,max_header_bytes=100)['status'],'pass')
        self.assertFalse((self.root/'executed').exists());self.assertEqual(p.stat().st_size,100010)
    def test_limits_symlink_and_permission(self):
        p=self.write(b'#!/bin/sh '+b'x'*200);self.assertIn('shebang_length_policy_exceeded',self.codes(tool.audit(p)));self.assertEqual(tool.audit(p,max_header_bytes=10)['status'],'error')
        q=self.root/'link';q.symlink_to(p);self.assertEqual(tool.audit(q)['status'],'error')
        with mock.patch.object(tool,'anchored',side_effect=PermissionError):self.assertEqual(tool.audit(p)['status'],'error')
    def test_nul_direct_args_and_env_options(self):
        self.assertIn('control_in_shebang',self.codes(tool.audit(self.write(b'#!/bin/sh\x00\n'))));self.assertIn('multiple_direct_arguments',self.codes(tool.audit(self.write(b'#!/bin/sh -e -x\n'))));self.assertIn('unsupported_env_command_or_options',self.codes(tool.audit(self.write(b'#!/usr/bin/env -i\n'))))

    def test_support_rejects_symlink_before_dotdot(self):
        import _support
        (self.root/'actual').mkdir();(self.root/'alias').symlink_to('actual');(self.root/'safe').write_bytes(b'x')
        with self.assertRaises((OSError,_support.InputError)):
            with _support.anchored(str(self.root)+'/alias/../safe'):
                self.fail('must not normalize away a symlink component')
    def test_support_detects_pre_read_mutation(self):
        import _support
        p=self.root/'changed';p.write_bytes(b'a');before=p.stat();p.write_bytes(b'longer')
        with _support.anchored(self.root,True) as fd:
            with self.assertRaises(_support.InputError):_support.read_at(fd,'changed',before,100)
    def test_support_entry_budget_and_host_guard(self):
        import _support
        (self.root/'a').mkdir();(self.root/'a'/'x').touch();(self.root/'b').touch()
        with _support.anchored(self.root,True) as fd:
            with self.assertRaises(_support.InputError):list(_support.walk(fd,max_entries=2))
        with mock.patch.object(_support.os,'name','unsupported'):
            with self.assertRaises(_support.InputError):_support._flags()

if __name__=="__main__":unittest.main()
