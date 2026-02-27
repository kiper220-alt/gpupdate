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

from util.logging import log
from util.xml import get_xml_root

from .dynamic_attributes import DynamicAttributes


VALID_POLICY_ELEMENTS = {
    'Service',
    'Socket',
    'Timer',
    'Path',
    'Mount',
    'Automount',
    'Swap',
    'Target',
    'Device',
    'Slice',
    'Scope',
}

VALID_STATES = {'as_is', 'enable', 'disable', 'mask', 'unmask', 'preset'}
VALID_APPLY_MODES = {'always', 'if_exists', 'if_missing'}
VALID_POLICY_TARGETS = {'machine', 'user'}
VALID_EDIT_MODES = {'create', 'override', 'create_or_override'}
VALID_DEP_MODES = {'changed', 'presence_changed'}
DEFAULT_DROPIN_NAME = '50-gpo.conf'

UNIT_SUFFIX = {
    'Service': '.service',
    'Socket': '.socket',
    'Timer': '.timer',
    'Path': '.path',
    'Mount': '.mount',
    'Automount': '.automount',
    'Swap': '.swap',
    'Target': '.target',
    'Device': '.device',
    'Slice': '.slice',
    'Scope': '.scope',
}


def _tag_name(element):
    return str(element.tag).split('}')[-1]


def _as_bool(value, default=False):
    if value is None:
        return default
    return str(value).lower() in ('1', 'true', 'yes')


def _normalize_unit_name(unit_name, element_name):
    if not unit_name:
        return None

    all_suffixes = set(UNIT_SUFFIX.values())
    if any(str(unit_name).endswith(suffix) for suffix in all_suffixes):
        return unit_name

    suffix = UNIT_SUFFIX.get(element_name)
    if not suffix:
        return unit_name

    return '{}{}'.format(unit_name, suffix)


def _is_safe_component(value):
    text = str(value) if value is not None else ''
    if not text:
        return False
    if text in ('.', '..'):
        return False
    if text != text.strip():
        return False
    if '/' in text or '\\' in text:
        return False
    if os.path.isabs(text):
        return False
    if len(text) >= 2 and text[1] == ':' and text[0].isalpha():
        return False
    if '\x00' in text:
        return False
    return True


def _invalid_entry(message, data=None):
    payload = {'reason': message}
    if data:
        payload.update(data)
    log('W47', payload)


def _parse_file_dependencies(properties):
    file_dependencies = []
    dependencies = properties.find('FileDependencies')
    if dependencies is None:
        return file_dependencies

    for dependency in dependencies.findall('Dependency'):
        mode = dependency.get('mode')
        path = dependency.get('path')
        if mode not in VALID_DEP_MODES or not path:
            _invalid_entry('Invalid dependency entry', {'mode': mode, 'path': path})
            continue
        file_dependencies.append({'mode': mode, 'path': path})

    return file_dependencies


def _parse_policy_element(policy_element):
    element_name = _tag_name(policy_element)
    if element_name not in VALID_POLICY_ELEMENTS:
        return None

    properties = policy_element.find('Properties')
    if properties is None:
        _invalid_entry('Missing <Properties> in Systemds element', {'element': element_name})
        return None

    unit = _normalize_unit_name(properties.get('unit'), element_name)
    state = properties.get('state')
    apply_mode = properties.get('applyMode', 'always')
    policy_target = properties.get('policyTarget', 'machine')
    edit_mode = properties.get('editMode', 'override')

    if not unit:
        _invalid_entry('Missing unit attribute', {'element': element_name})
        return None
    if not _is_safe_component(unit):
        _invalid_entry('Invalid unit value', {'element': element_name, 'unit': unit})
        return None
    if state not in VALID_STATES:
        _invalid_entry('Invalid state', {'element': element_name, 'state': state, 'unit': unit})
        return None
    if apply_mode not in VALID_APPLY_MODES:
        _invalid_entry('Invalid applyMode', {'element': element_name, 'apply_mode': apply_mode, 'unit': unit})
        return None
    if policy_target not in VALID_POLICY_TARGETS:
        _invalid_entry('Invalid policyTarget', {'element': element_name, 'policy_target': policy_target, 'unit': unit})
        return None
    if edit_mode not in VALID_EDIT_MODES:
        _invalid_entry('Invalid editMode', {'element': element_name, 'edit_mode': edit_mode, 'unit': unit})
        return None

    uid = policy_element.get('uid')
    clsid = policy_element.get('clsid')
    name = policy_element.get('name')
    if not uid or not clsid or not name:
        _invalid_entry('Missing required policy attributes', {
            'element': element_name,
            'uid': uid,
            'clsid': clsid,
            'name': name,
            'unit': unit,
        })
        return None

    unit_file = properties.find('UnitFile')
    unit_file_text = None
    if unit_file is not None and unit_file.text is not None:
        # UnitFile mode=table is treated as plain text by design.
        unit_file_text = str(unit_file.text)

    policy = systemd_policy(unit)
    policy.element_type = element_name.lower()
    policy.clsid = clsid
    policy.name = name
    policy.status = policy_element.get('status')
    policy.image = policy_element.get('image')
    policy.changed = policy_element.get('changed')
    policy.uid = uid
    policy.desc = policy_element.get('desc')
    policy.bypassErrors = policy_element.get('bypassErrors')
    policy.userContext = policy_element.get('userContext')
    policy.removePolicy = policy_element.get('removePolicy')

    policy.state = state
    policy.now = _as_bool(properties.get('now'), default=False)
    policy.apply_mode = apply_mode
    policy.policy_target = policy_target
    policy.edit_mode = edit_mode
    dropin_name = properties.get('dropInName', DEFAULT_DROPIN_NAME) or DEFAULT_DROPIN_NAME
    if not _is_safe_component(dropin_name):
        _invalid_entry('Invalid dropInName', {'element': element_name, 'dropInName': dropin_name, 'unit': unit})
        return None

    policy.dropin_name = dropin_name
    policy.unit_file = unit_file_text
    policy.unit_file_mode = 'text'
    policy.file_dependencies = _parse_file_dependencies(properties)

    return policy


def read_systemds(systemds_file):
    """
    Read Systemds.xml from GPT.
    """
    policies = []
    root = get_xml_root(systemds_file)
    if _tag_name(root) != 'Systemds':
        _invalid_entry('Unexpected root element in Systemds.xml', {'root': _tag_name(root)})
        return policies

    for policy_element in root:
        parsed = _parse_policy_element(policy_element)
        if parsed is not None:
            policies.append(parsed)

    return policies


def merge_systemds(storage, systemd_objects, policy_name):
    for systemd_object in systemd_objects:
        storage.add_systemd(systemd_object, policy_name)


class systemd_policy(DynamicAttributes):
    def __init__(self, unit):
        self.unit = unit
