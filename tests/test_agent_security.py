"""Isolated source regression tests: no GUI, LAN scan, or cloud requests."""
import ast
import ipaddress
from pathlib import Path
import re
import socket
import threading
import time
import types
import unittest
from unittest.mock import Mock
import urllib.parse
import xml.etree.ElementTree as ET

SOURCE = Path(__file__).resolve().parents[1] / 'agent/wifi_watch_agent.py'
TREE = ast.parse(SOURCE.read_text())
CLASS = next(n for n in TREE.body if isinstance(n, ast.ClassDef) and n.name == 'WiFiWatchApp')


def functions(names, methods=False, **extra):
    scope = dict(ipaddress=ipaddress, socket=socket, urllib=urllib, ET=ET,
                 time=time, re=re, threading=threading, APP_VERSION='test',
                 BAD_VALUES=set(), log=lambda *a: None)
    scope.update(extra)
    nodes = [n for n in (CLASS.body if methods else TREE.body)
             if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(nodes) == len(names)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), 'exec'), scope)
    return scope


class AgentSecurity(unittest.TestCase):
    def test_destination_is_pinned_and_local(self):
        resolver = Mock(return_value='192.168.1.3')
        scope = functions(['resolve_upnp_location'], socket=types.SimpleNamespace(gethostbyname=resolver))
        resolve = scope['resolve_upnp_location']
        net = ipaddress.ip_network('192.168.1.0/24')
        self.assertEqual(resolve('http://device.local:80/device.xml', net),
                         ('http://192.168.1.3:80/device.xml', 'device.local:80'))
        resolver.assert_called_once_with('device.local')
        for url in ['http://8.8.8.8/', 'http://127.0.0.1/', 'http://[::1]/',
                    'file:///etc/passwd', 'http://user:password@192.168.1.3/',
                    'http://192.168.1.3:99999/', 'http://192.168.1.3/\r\nx']:
            self.assertIsNone(resolve(url, net), url)

    def upnp(self, chunks, headers=None):
        response = Mock(ok=True, headers=headers or {})
        response.iter_content.return_value = iter(chunks)
        session = Mock()
        session.get.return_value = response
        scope = functions(['resolve_upnp_location', 'upnp_identity', 'xml_value',
                           'clean_identity_text', 'valid_model'],
                          requests=types.SimpleNamespace(Session=lambda: session))
        result = scope['upnp_identity']('http://192.168.1.3/device.xml', ipaddress.ip_network('192.168.1.0/24'))
        self.assertTrue(session.get.call_args.kwargs['stream'])
        self.assertFalse(session.get.call_args.kwargs['allow_redirects'])
        self.assertFalse(session.trust_env)
        session.close.assert_called_once()
        response.close.assert_called_once()
        return result, response

    def test_upnp_normal_identity(self):
        result, _ = self.upnp([b'<root><friendlyName>Living Room</friendlyName><modelName>Model A</modelName></root>'])
        self.assertEqual(result['friendly_name'], 'Living Room')
        self.assertEqual(result['model'], 'Model A')

    def test_upnp_oversize_without_length(self):
        def chunks():
            for _ in range(129):
                yield b'x' * 4096
            raise AssertionError('Must stop reading at limit')
        result, _ = self.upnp(chunks())
        self.assertIsNone(result)

    def test_upnp_rejects_large_declared_length_before_read(self):
        result, response = self.upnp([], {'Content-Length': '524289'})
        self.assertIsNone(result)
        response.iter_content.assert_not_called()

    def test_pairing_callback_captures_error(self):
        callbacks, errors = [], []
        scope = functions(['pair_worker'], methods=True,
                          claim_pairing_code=Mock(side_effect=RuntimeError('pair failure')))
        app = types.SimpleNamespace(scan_lock=threading.Lock(), is_paired=lambda: False,
                                    root=types.SimpleNamespace(after=lambda delay, fn: callbacks.append(fn)),
                                    pair_error=errors.append, pairing_busy=True)
        scope['pair_worker'](app, 'code')
        callbacks[0]()
        self.assertEqual(errors, ['pair failure'])
        self.assertFalse(app.pairing_busy)

    def scan(self, action):
        callbacks, uploads, errors = [], [], []
        app = types.SimpleNamespace(config={'agent_id': 'old', 'agent_secret': 'old'},
            scan_lock=threading.Lock(), stop_event=threading.Event(), disconnecting=False,
            is_paired=lambda: True, root=types.SimpleNamespace(after=lambda delay, fn: callbacks.append(fn)),
            status_value=Mock(), scan_success=Mock(), scan_error=errors.append)
        def scan(config, **kwargs):
            action(app)
            return dict(devices=[{'ip': '192.168.1.3'}], network='192.168.1.0/24',
                        local_ip='192.168.1.2', ruleset_version='test', learned_rules=0, duration_ms=1)
        scope = functions(['perform_scan'], methods=True, heartbeat=lambda config: None,
            scan_network=scan, sync_devices=lambda config, devices: uploads.append(config['agent_id']),
            report_scan=lambda *args: None)
        scope['perform_scan'](app)
        for callback in callbacks:
            callback()
        self.assertFalse(app.scan_lock.locked())
        return uploads, errors

    def test_scan_uses_original_credentials(self):
        uploads, _ = self.scan(lambda app: setattr(app, 'config', {'agent_id': 'new'}))
        self.assertEqual(uploads, ['old'])

    def test_disconnected_scan_does_not_upload(self):
        uploads, _ = self.scan(lambda app: app.stop_event.set())
        self.assertEqual(uploads, [])

    def test_scan_callback_captures_error(self):
        def fail(app):
            raise RuntimeError('scan failure')
        uploads, errors = self.scan(fail)
        self.assertEqual(uploads, [])
        self.assertEqual(errors, ['scan failure'])

    def test_disconnect_waits_for_scan_lock(self):
        deleted = threading.Event()
        scope = functions(['disconnect_worker'], methods=True, delete_config=deleted.set)
        app = types.SimpleNamespace(scan_lock=threading.Lock(), config={'agent_id': 'old'},
                                    root=Mock(), finish_disconnect=Mock())
        app.scan_lock.acquire()
        worker = threading.Thread(target=scope['disconnect_worker'], args=(app,))
        worker.start()
        self.assertFalse(deleted.wait(0.03))
        self.assertEqual(app.config['agent_id'], 'old')
        app.scan_lock.release()
        worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertTrue(deleted.is_set())
        self.assertEqual(app.config, {})


if __name__ == '__main__':
    unittest.main()
