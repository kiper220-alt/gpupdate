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
import unittest
import unittest.mock


class _storage_stub:
    def __init__(self, values=None):
        self.values = values or {}

    def get_entry(self, path, dictionary=None, preg=True):
        return self.values.get(path)

    def get_key_value(self, path):
        return None


def _load_spa():
    if 'frontend' not in sys.modules:
        frontend_pkg = types.ModuleType('frontend')
        frontend_pkg.__path__ = [os.path.join(os.getcwd(), 'frontend')]
        sys.modules['frontend'] = frontend_pkg
    return importlib.import_module('frontend.systemd_preferences_applier')


class SystemdPreferencesApplierTestCase(unittest.TestCase):
    def test_apply_mode_skips_non_matching_rules(self):
        spa = _load_spa()

        commands = []

        def fake_run(command):
            commands.append(command)
            if any('LoadState' in part for part in command):
                unit_name = command[-1]
                if unit_name == 'exists.service':
                    return 0, 'loaded', ''
                return 0, 'not-found', ''
            return 0, '', ''

        storage = _storage_stub()
        runtime = spa._systemd_preferences_runtime(storage, 'Machine', spa._Context(mode='machine'))
        with unittest.mock.patch('frontend.systemd_preferences_applier._run_command', side_effect=fake_run):
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

        self.assertIn(['/bin/systemctl', 'enable', 'exists.service'], commands)
        self.assertNotIn(['/bin/systemctl', 'enable', 'missing.service'], commands)
        self.assertNotIn(['/bin/systemctl', 'disable', 'exists.service'], commands)

    def test_edit_mode_create_or_override_writes_expected_paths(self):
        spa = _load_spa()

        commands = []

        def fake_run(command):
            commands.append(command)
            if any('LoadState' in part for part in command):
                unit_name = command[-1]
                if unit_name == 'exists.service':
                    return 0, 'loaded', ''
                return 0, 'not-found', ''
            return 0, '', ''

        storage = _storage_stub()
        runtime = spa._systemd_preferences_runtime(storage, 'Machine', spa._Context(mode='machine'))
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime.context.systemd_dir = tmpdir
            with unittest.mock.patch('frontend.systemd_preferences_applier._run_command', side_effect=fake_run):
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
            self.assertIn(['/bin/systemctl', 'daemon-reload'], commands)

    def test_post_restart_uses_dependency_modes(self):
        spa = _load_spa()

        commands = []

        def fake_run(command):
            commands.append(command)
            if any('ActiveState' in part for part in command):
                return 0, 'active', ''
            return 0, '', ''

        storage = _storage_stub()
        runtime = spa._systemd_preferences_runtime(storage, 'Machine', spa._Context(mode='machine'))
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

        with unittest.mock.patch('frontend.systemd_preferences_applier._run_command', side_effect=fake_run):
            with unittest.mock.patch('frontend.systemd_preferences_applier.query') as query_mock:
                query_mock.side_effect = lambda path, mode='changed': mode == 'changed'
                runtime.post_restart()

        self.assertIn(['/bin/systemctl', 'restart', 'demo.service'], commands)

    def test_post_restart_skips_when_dependency_unchanged(self):
        spa = _load_spa()

        commands = []

        def fake_run(command):
            commands.append(command)
            if any('ActiveState' in part for part in command):
                return 0, 'active', ''
            return 0, '', ''

        storage = _storage_stub()
        runtime = spa._systemd_preferences_runtime(storage, 'Machine', spa._Context(mode='machine'))
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

        with unittest.mock.patch('frontend.systemd_preferences_applier._run_command', side_effect=fake_run):
            with unittest.mock.patch('frontend.systemd_preferences_applier.query', return_value=False):
                runtime.post_restart()

        self.assertNotIn(['/bin/systemctl', 'restart', 'demo.service'], commands)

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

        commands = []

        def fake_run(command):
            commands.append(command)
            if any('ActiveState' in part for part in command):
                return 0, 'active', ''
            return 0, '', ''

        storage = _storage_stub()
        runtime = spa._systemd_preferences_runtime(storage, 'Machine', spa._Context(mode='machine'))

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

            with unittest.mock.patch('frontend.systemd_preferences_applier._run_command', side_effect=fake_run):
                runtime.cleanup_removed_rules([removed_rule])

            self.assertFalse(os.path.exists(managed))
            self.assertIn(['/bin/systemctl', 'daemon-reload'], commands)
            self.assertNotIn(['/bin/systemctl', 'restart', 'usb.device'], commands)

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
