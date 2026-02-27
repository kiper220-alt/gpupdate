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

import os
import unittest
import unittest.mock


class _storage_stub:
    def __init__(self):
        self.items = []

    def add_systemd(self, item, policy_name):
        item.policy_name = policy_name
        self.items.append(item)


class GptSystemdsTestCase(unittest.TestCase):
    def _path(self, filename):
        return '{}/test/gpt/data/{}'.format(os.getcwd(), filename)

    def test_read_systemds_all_types(self):
        import gpt.systemds

        items = gpt.systemds.read_systemds(self._path('Systemds.xml'))
        self.assertEqual(len(items), 11)
        self.assertEqual(items[0].unit, 'sshd.service')
        self.assertEqual(items[0].state, 'enable')
        self.assertEqual(items[0].apply_mode, 'always')
        self.assertEqual(items[0].policy_target, 'machine')
        self.assertEqual(items[0].edit_mode, 'override')
        self.assertEqual(items[0].dropin_name, 'override.conf')
        self.assertEqual(items[0].unit_file_mode, 'text')
        self.assertEqual(len(items[0].file_dependencies), 2)

        # Ensure automatic suffix mapping works for all supported tags.
        expected_suffixes = {
            'service': '.service',
            'socket': '.socket',
            'timer': '.timer',
            'path': '.path',
            'mount': '.mount',
            'automount': '.automount',
            'swap': '.swap',
            'target': '.target',
            'device': '.device',
            'slice': '.slice',
            'scope': '.scope',
        }
        for item in items:
            self.assertTrue(item.unit.endswith(expected_suffixes[item.element_type]))

    def test_soft_validation_skips_invalid_entries(self):
        import gpt.systemds

        items = gpt.systemds.read_systemds(self._path('Systemds_invalid.xml'))
        # good + bad-dep (kept with filtered deps); invalid path values are skipped
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].unit, 'good.service')
        self.assertEqual(items[1].unit, 'bad3.service')
        self.assertEqual(items[1].file_dependencies, [])
        units = {item.unit for item in items}
        self.assertNotIn('../../tmp/evil.service', units)
        self.assertNotIn('safe.service', units)

    def test_merge_systemds(self):
        import gpt.systemds

        storage = _storage_stub()
        items = gpt.systemds.read_systemds(self._path('Systemds.xml'))
        gpt.systemds.merge_systemds(storage, items, 'policy-test')
        self.assertEqual(len(storage.items), len(items))
        self.assertEqual(storage.items[0].policy_name, 'policy-test')


if __name__ == '__main__':
    unittest.main()
