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

import unittest

from gpt.systemds import systemd_policy


class SystemdsStorageTestCase(unittest.TestCase):
    def setUp(self):
        try:
            from storage.dconf_registry import Dconf_registry
        except Exception as exc:
            self.skipTest('storage.dconf_registry is unavailable: {}'.format(exc))
        self.Dconf_registry = Dconf_registry
        self.add_preferences_to_global_registry_dict = __import__(
            'storage.dconf_registry', fromlist=['add_preferences_to_global_registry_dict']
        ).add_preferences_to_global_registry_dict

        self._saved_registry = self.Dconf_registry.global_registry_dict
        self._saved_systemds = self.Dconf_registry.systemds

        self.Dconf_registry.global_registry_dict = {self.Dconf_registry._GpoPriority: {}}
        self.Dconf_registry.systemds = []

    def tearDown(self):
        if hasattr(self, 'Dconf_registry'):
            self.Dconf_registry.global_registry_dict = self._saved_registry
            self.Dconf_registry.systemds = self._saved_systemds

    def test_add_get_and_serialize_systemds(self):
        item = systemd_policy('sshd.service')
        item.uid = 'uid-1'
        item.clsid = 'clsid-1'
        item.name = 'sshd'
        item.state = 'enable'
        item.policy_target = 'machine'
        item.apply_mode = 'always'
        item.edit_mode = 'override'
        item.dropin_name = '50-gpo.conf'
        item.file_dependencies = []
        self.Dconf_registry.add_systemd(item, 'Policy')

        self.assertEqual(len(self.Dconf_registry.get_systemds()), 1)
        self.add_preferences_to_global_registry_dict('Machine', True)

        prefix = 'Software/BaseALT/Policies/Preferences/Machine'
        data = self.Dconf_registry.global_registry_dict[prefix]['Systemds']
        self.assertIn('sshd.service', data)
        self.assertIn('uid-1', data)


if __name__ == '__main__':
    unittest.main()
