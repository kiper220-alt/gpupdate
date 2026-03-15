#
# GPOA - GPO Applier for Linux
#
# Copyright (C) 2026 BaseALT Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import tempfile
import os
import sys
import types
import importlib
import base64
import unittest
import unittest.mock
from pathlib import Path


class _storage_stub:
    def __init__(self, values=None):
        self.values = values or {}

    def get_entry(self, path, dictionary=None, preg=True):
        return self.values.get(path)

    def get_key_value(self, path):
        return None


class _manager_stub:
    def __init__(self, exists_map=None, active_state_map=None):
        self.exists_map = exists_map or {}
        self.active_state_map = active_state_map or {}
        self.exists_calls = []
        self.apply_state_calls = []
        self.restart_calls = []
        self.reload_calls = 0

    def exists(self, unit_name):
        self.exists_calls.append(unit_name)
        return self.exists_map.get(unit_name, False)

    def reload(self):
        self.reload_calls += 1

    def active_state(self, unit_name):
        return self.active_state_map.get(unit_name, 'inactive')

    def restart(self, unit_name):
        self.restart_calls.append(unit_name)

    def apply_state(self, unit_name, state, now):
        self.apply_state_calls.append((unit_name, state, now))


def _load_spa():
    if 'frontend' not in sys.modules:
        frontend_pkg = types.ModuleType('frontend')
        frontend_pkg.__path__ = [os.path.join(os.getcwd(), 'frontend')]
        sys.modules['frontend'] = frontend_pkg
    return importlib.import_module('frontend.systemd_preferences_applier')


class SystemdPreferencesApplierTestCase(unittest.TestCase):
    def test_apply_mode_skips_non_matching_rules(self):
        spa = _load_spa()

        storage = _storage_stub()
        runtime = spa._systemd_preferences_runtime(storage, 'Machine', spa._Context(mode='machine'))
        manager = _manager_stub(exists_map={
            'exists.service': True,
            'missing.service': False,
        })
        runtime.systemd_manager = manager
        runtime.apply_rules([
            {
                'uid': '1',
                'unit': 'missing.service',
                'state': 'enable',
                'now': False,
                'apply_mode': 'if_exists',
                'policy_target': 'machine',
                'edit_mode': 'override',
                'dropin_name': '50-gpo.conf',
                'unit_file': None,
                'file_dependencies': [],
                'element_type': 'service',
            },
            {
                'uid': '2',
                'unit': 'exists.service',
                'state': 'disable',
                'now': False,
                'apply_mode': 'if_missing',
                'policy_target': 'machine',
                'edit_mode': 'override',
                'dropin_name': '50-gpo.conf',
                'unit_file': None,
                'file_dependencies': [],
                'element_type': 'service',
            },
            {
                'uid': '3',
                'unit': 'exists.service',
                'state': 'enable',
                'now': False,
                'apply_mode': 'always',
                'policy_target': 'machine',
                'edit_mode': 'override',
                'dropin_name': '50-gpo.conf',
                'unit_file': None,
                'file_dependencies': [],
                'element_type': 'service',
            },
        ])

        self.assertEqual(manager.apply_state_calls, [('exists.service', 'enable', False)])

    def test_edit_mode_create_or_override_writes_expected_paths(self):
        spa = _load_spa()

        storage = _storage_stub()
        runtime = spa._systemd_preferences_runtime(storage, 'Machine', spa._Context(mode='machine'))
        runtime.systemd_manager = _manager_stub(exists_map={
            'exists.service': True,
            'new.service': False,
        })
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime.context.systemd_dir = tmpdir
            runtime.apply_rules([
                {
                    'uid': '10',
                    'unit': 'exists.service',
                    'state': 'as_is',
                    'now': False,
                    'apply_mode': 'always',
                    'policy_target': 'machine',
                    'edit_mode': 'create_or_override',
                    'dropin_name': 'custom.conf',
                    'unit_file': '[Service]\nRestart=always',
                    'file_dependencies': [],
                    'element_type': 'service',
                },
                {
                    'uid': '11',
                    'unit': 'new.service',
                    'state': 'as_is',
                    'now': False,
                    'apply_mode': 'always',
                    'policy_target': 'machine',
                    'edit_mode': 'create_or_override',
                    'dropin_name': 'custom.conf',
                    'unit_file': '[Service]\nRestart=no',
                    'file_dependencies': [],
                    'element_type': 'service',
                },
            ])

            dropin_path = '{}/exists.service.d/custom.conf'.format(tmpdir)
            create_path = '{}/new.service'.format(tmpdir)
            with open(dropin_path, 'r', encoding='utf-8') as fh:
                self.assertIn('gpupdate-managed uid: 10', fh.read())
            with open(create_path, 'r', encoding='utf-8') as fh:
                self.assertIn('gpupdate-managed uid: 11', fh.read())
            self.assertGreaterEqual(runtime.systemd_manager.reload_calls, 1)

    def test_normalize_rule_unescapes_newline_sequences_in_unit_file(self):
        spa = _load_spa()

        normalized = spa._normalize_rule({
            'uid': '12',
            'unit': 'escaped.service',
            'state': 'as_is',
            'now': False,
            'apply_mode': 'always',
            'policy_target': 'machine',
            'edit_mode': 'override',
            'dropin_name': '50-gpo.conf',
            'unit_file': '[Service]\\nRestart=always',
            'file_dependencies': [],
            'element_type': 'service',
        })

        self.assertEqual(normalized['unit_file'], '[Service]\nRestart=always')

    def test_normalize_rule_decodes_unit_file_b64_with_priority(self):
        spa = _load_spa()

        original = "[Service]\nExecStart=/bin/bash -c \"echo 'ok'\"\n"
        encoded = base64.b64encode(original.encode('utf-8')).decode('ascii')
        normalized = spa._normalize_rule({
            'uid': '13',
            'unit': 'encoded.service',
            'state': 'as_is',
            'now': False,
            'apply_mode': 'always',
            'policy_target': 'machine',
            'edit_mode': 'override',
            'dropin_name': '50-gpo.conf',
            'unit_file_b64': encoded,
            'unit_file': '[Service]\\nExecStart=/bin/false',
            'file_dependencies': [],
            'element_type': 'service',
        })

        self.assertEqual(normalized['unit_file'], original)

    def test_normalize_rule_falls_back_to_legacy_when_unit_file_b64_invalid(self):
        spa = _load_spa()

        with unittest.mock.patch('frontend.systemd_preferences_applier.log') as log_mock:
            normalized = spa._normalize_rule({
                'uid': '14',
                'unit': 'encoded.service',
                'state': 'as_is',
                'now': False,
                'apply_mode': 'always',
                'policy_target': 'machine',
                'edit_mode': 'override',
                'dropin_name': '50-gpo.conf',
                'unit_file_b64': 'invalid-%%%',
                'unit_file': '[Service]\\nRestart=always',
                'file_dependencies': [],
                'element_type': 'service',
            })

        self.assertEqual(normalized['unit_file'], '[Service]\nRestart=always')
        log_mock.assert_any_call('W47', {
            'reason': 'Invalid unit_file_b64 payload',
            'unit': 'encoded.service',
            'uid': '14',
        })

    def test_normalize_rule_rejects_too_many_dependencies(self):
        spa = _load_spa()

        too_many = [{'mode': 'changed', 'path': '/etc/demo{}'.format(idx)} for idx in range(64)]
        normalized = spa._normalize_rule({
            'uid': '15',
            'unit': 'demo.service',
            'state': 'as_is',
            'apply_mode': 'always',
            'policy_target': 'machine',
            'edit_mode': 'override',
            'dropin_name': '50-gpo.conf',
            'file_dependencies': too_many,
        })
        self.assertIsNone(normalized)

    def test_normalize_rule_filters_invalid_dependency_paths(self):
        spa = _load_spa()

        normalized = spa._normalize_rule({
            'uid': '16',
            'unit': 'demo.service',
            'state': 'as_is',
            'apply_mode': 'always',
            'policy_target': 'machine',
            'edit_mode': 'override',
            'dropin_name': '50-gpo.conf',
            'file_dependencies': [
                {'mode': 'changed', 'path': '/etc/demo.conf'},
                {'mode': 'changed', 'path': '../relative'},
                {'mode': 'changed', 'path': '/tmp/\ninvalid'},
            ],
        })
        self.assertEqual(normalized['file_dependencies'], [{'mode': 'changed', 'path': '/etc/demo.conf'}])

    def test_normalize_rule_rejects_oversized_unit_file(self):
        spa = _load_spa()

        huge_payload = 'A' * (spa.MAX_UNIT_FILE_SIZE + 1)
        encoded = base64.b64encode(huge_payload.encode('utf-8')).decode('ascii')
        normalized = spa._normalize_rule({
            'uid': '17',
            'unit': 'huge.service',
            'state': 'as_is',
            'apply_mode': 'always',
            'policy_target': 'machine',
            'edit_mode': 'override',
            'dropin_name': '50-gpo.conf',
            'unit_file_b64': encoded,
        })
        self.assertIsNone(normalized['unit_file'])

    def test_post_restart_uses_dependency_modes(self):
        spa = _load_spa()

        storage = _storage_stub()
        runtime = spa._systemd_preferences_runtime(storage, 'Machine', spa._Context(mode='machine'))
        runtime.systemd_manager = _manager_stub(active_state_map={'demo.service': 'active'})
        runtime.phase2_candidates = [{
            'uid': '1',
            'unit': 'demo.service',
            'state': 'as_is',
            'now': False,
            'apply_mode': 'always',
            'policy_target': 'machine',
            'edit_mode': 'override',
            'dropin_name': '50-gpo.conf',
            'unit_file': None,
            'file_dependencies': [
                {'mode': 'changed', 'path': '/etc/demo.conf'},
                {'mode': 'presence_changed', 'path': '/etc/demo.presence'},
            ],
            'element_type': 'service',
        }]

        with unittest.mock.patch('frontend.systemd_preferences_applier.query') as query_mock:
            query_mock.side_effect = lambda path, mode='changed': mode == 'changed'
            runtime.post_restart()

        self.assertIn('demo.service', runtime.systemd_manager.restart_calls)

    def test_post_restart_skips_when_dependency_unchanged(self):
        spa = _load_spa()

        storage = _storage_stub()
        runtime = spa._systemd_preferences_runtime(storage, 'Machine', spa._Context(mode='machine'))
        runtime.systemd_manager = _manager_stub(active_state_map={'demo.service': 'active'})
        runtime.phase2_candidates = [{
            'uid': '1',
            'unit': 'demo.service',
            'state': 'as_is',
            'now': False,
            'apply_mode': 'always',
            'policy_target': 'machine',
            'edit_mode': 'override',
            'dropin_name': '50-gpo.conf',
            'unit_file': None,
            'file_dependencies': [
                {'mode': 'changed', 'path': '/etc/demo.conf'},
            ],
            'element_type': 'service',
        }]

        with unittest.mock.patch('frontend.systemd_preferences_applier.query', return_value=False):
            runtime.post_restart()

        self.assertNotIn('demo.service', runtime.systemd_manager.restart_calls)

    def test_removed_rules_detected_from_previous_snapshot(self):
        spa = _load_spa()

        storage = _storage_stub({
            'Software/BaseALT/Policies/Preferences/Machine/Systemds': str([{
                'uid': 'keep',
                'unit': 'keep.service',
                'state': 'enable',
                'apply_mode': 'always',
                'policy_target': 'machine',
                'edit_mode': 'override',
            }]),
            'Previous/Software/BaseALT/Policies/Preferences/Machine/Systemds': str([
                {
                    'uid': 'keep',
                    'unit': 'keep.service',
                    'state': 'enable',
                    'apply_mode': 'always',
                    'policy_target': 'machine',
                    'edit_mode': 'override',
                },
                {
                    'uid': 'drop',
                    'unit': 'drop.service',
                    'state': 'enable',
                    'apply_mode': 'always',
                    'policy_target': 'machine',
                    'edit_mode': 'override',
                },
            ]),
        })
        removed = spa._get_removed_rules(storage, 'Machine', 'machine')
        self.assertEqual(len(removed), 1)
        self.assertEqual(removed[0]['uid'], 'drop')

    def test_normalize_rule_rejects_unsafe_unit_and_dropin_paths(self):
        spa = _load_spa()

        bad_unit = {
            'uid': 'bad-unit',
            'unit': '/tmp/evil.service',
            'state': 'enable',
            'apply_mode': 'always',
            'policy_target': 'machine',
            'edit_mode': 'override',
        }
        bad_dropin = {
            'uid': 'bad-dropin',
            'unit': 'safe.service',
            'state': 'enable',
            'apply_mode': 'always',
            'policy_target': 'machine',
            'edit_mode': 'override',
            'dropInName': '../../evil.conf',
        }
        self.assertIsNone(spa._normalize_rule(bad_unit))
        self.assertIsNone(spa._normalize_rule(bad_dropin))

    def test_cleanup_removed_rules_keeps_non_restartable_types_skipped(self):
        spa = _load_spa()

        storage = _storage_stub()
        runtime = spa._systemd_preferences_runtime(storage, 'Machine', spa._Context(mode='machine'))
        runtime.systemd_manager = _manager_stub(active_state_map={'usb.device': 'active'})

        with tempfile.TemporaryDirectory() as tmpdir:
            runtime.context.systemd_dir = tmpdir
            managed = os.path.join(tmpdir, 'usb.device')
            with open(managed, 'w', encoding='utf-8') as file_obj:
                file_obj.write('# gpupdate-managed uid: deadbeef\n[Unit]\nDescription=test\n')

            removed_rule = {
                'uid': 'deadbeef',
                'unit': 'usb.device',
                'dropin_name': '50-gpo.conf',
                'element_type': 'device',
            }

            runtime.cleanup_removed_rules([removed_rule])

            self.assertFalse(os.path.exists(managed))
            self.assertEqual(runtime.systemd_manager.reload_calls, 1)
            self.assertNotIn('usb.device', runtime.systemd_manager.restart_calls)

    def test_cleanup_removed_rules_requires_marker_on_first_line(self):
        spa = _load_spa()

        storage = _storage_stub()
        runtime = spa._systemd_preferences_runtime(storage, 'Machine', spa._Context(mode='machine'))
        runtime.systemd_manager = _manager_stub(active_state_map={'demo.service': 'active'})

        with tempfile.TemporaryDirectory() as tmpdir:
            runtime.context.systemd_dir = tmpdir
            managed = os.path.join(tmpdir, 'demo.service')
            with open(managed, 'w', encoding='utf-8') as file_obj:
                file_obj.write('[Unit]\n# gpupdate-managed uid: deadbeef\nDescription=test\n')

            removed_rule = {
                'uid': 'deadbeef',
                'unit': 'demo.service',
                'dropin_name': '50-gpo.conf',
                'element_type': 'service',
            }
            runtime.cleanup_removed_rules([removed_rule])

            self.assertTrue(os.path.exists(managed))
            self.assertEqual(runtime.systemd_manager.reload_calls, 0)

    def test_write_rule_file_skips_symlink_target(self):
        spa = _load_spa()

        storage = _storage_stub()
        runtime = spa._systemd_preferences_runtime(storage, 'Machine', spa._Context(mode='machine'))
        runtime.systemd_manager = _manager_stub()

        with tempfile.TemporaryDirectory() as tmpdir:
            runtime.context.systemd_dir = tmpdir
            real_target = os.path.join(tmpdir, 'real.service')
            with open(real_target, 'w', encoding='utf-8') as file_obj:
                file_obj.write('real')

            symlink_target = os.path.join(tmpdir, 'evil.service')
            os.symlink(real_target, symlink_target)

            runtime._write_rule_file(Path(symlink_target), 'uid-1', '[Unit]\nDescription=test')
            with open(real_target, 'r', encoding='utf-8') as file_obj:
                self.assertEqual(file_obj.read(), 'real')

    def test_user_context_skips_when_user_manager_unavailable(self):
        spa = _load_spa()

        storage = _storage_stub()
        with unittest.mock.patch('frontend.systemd_preferences_applier.check_enabled', return_value=True):
            applier = spa.systemd_preferences_applier_user(storage, 'root')
            with unittest.mock.patch('os.path.exists', return_value=False):
                with unittest.mock.patch('frontend.systemd_preferences_applier._systemd_preferences_runtime.apply_rules') as apply_mock:
                    applier.user_context_apply()
                    self.assertFalse(apply_mock.called)

    def test_prime_dependency_journal_machine_watches_machine_dependencies(self):
        spa = _load_spa()

        storage = _storage_stub({
            'Software/BaseALT/Policies/Preferences/Machine/Systemds': str([{
                'uid': 'rule-1',
                'unit': 'demo.service',
                'state': 'as_is',
                'apply_mode': 'always',
                'policy_target': 'machine',
                'edit_mode': 'override',
                'file_dependencies': [
                    {'mode': 'changed', 'path': '/etc/demo.conf'},
                ],
            }]),
        })

        with unittest.mock.patch('frontend.systemd_preferences_applier.check_enabled', return_value=True):
            applier = spa.systemd_preferences_applier(storage)
            with unittest.mock.patch('frontend.systemd_preferences_applier.watch_many') as watch_many_mock:
                applier.prime_dependency_journal()
                watch_many_mock.assert_called_once_with(['/etc/demo.conf'])

    def test_prime_dependency_journal_user_watches_machine_and_user_dependencies(self):
        spa = _load_spa()

        storage = _storage_stub({
            'Software/BaseALT/Policies/Preferences/alice/Systemds': str([
                {
                    'uid': 'rule-machine',
                    'unit': 'demo.service',
                    'state': 'as_is',
                    'apply_mode': 'always',
                    'policy_target': 'machine',
                    'edit_mode': 'override',
                    'file_dependencies': [
                        {'mode': 'changed', 'path': '/etc/demo.conf'},
                    ],
                },
                {
                    'uid': 'rule-user',
                    'unit': 'demo.service',
                    'state': 'as_is',
                    'apply_mode': 'always',
                    'policy_target': 'user',
                    'edit_mode': 'override',
                    'file_dependencies': [
                        {'mode': 'changed', 'path': '%HOME%/.config/demo.conf'},
                    ],
                },
            ]),
        })

        with unittest.mock.patch('frontend.systemd_preferences_applier.check_enabled', return_value=True):
            with unittest.mock.patch('frontend.systemd_preferences_applier.get_uid_by_username', return_value=1000):
                with unittest.mock.patch('frontend.systemd_preferences_applier.get_homedir', return_value='/home/alice'):
                    applier = spa.systemd_preferences_applier_user(storage, 'alice')
                    with unittest.mock.patch('frontend.systemd_preferences_applier.watch_many') as watch_many_mock:
                        applier.prime_dependency_journal()
                        expected_user_path = spa._expand_windows_var('%HOME%/.config/demo.conf', username='alice')
                        watch_many_mock.assert_called_once_with(['/etc/demo.conf', expected_user_path])


if __name__ == '__main__':
    unittest.main()
