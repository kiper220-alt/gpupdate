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
from pathlib import Path
import subprocess

from util.logging import log
from util.util import get_homedir, get_uid_by_username, string_to_literal_eval

from .applier_frontend import applier_frontend, check_enabled
from .change_journal import query, record_changed, record_presence_changed, watch_many


DEFAULT_DROPIN_NAME = '50-gpo.conf'
MANAGED_HEADER = '# gpupdate-managed uid: {}'
VALID_STATES = {'as_is', 'enable', 'disable', 'mask', 'unmask', 'preset'}
VALID_APPLY_MODES = {'always', 'if_exists', 'if_missing'}
VALID_POLICY_TARGETS = {'machine', 'user'}
VALID_EDIT_MODES = {'create', 'override', 'create_or_override'}
VALID_DEP_MODES = {'changed', 'presence_changed'}
NON_RESTARTABLE_TYPES = {'device', 'scope'}


class _Context:
    def __init__(self, mode='machine', username=None):
        self.mode = mode
        self.username = username
        self.systemd_dir = '/etc/systemd/system'
        self.systemctl_base = ['/bin/systemctl']
        if mode == 'user':
            self.systemctl_base = ['/bin/systemctl', '--user']
            self.systemd_dir = os.path.join(get_homedir(username), '.config/systemd/user')


def _syslog(level, message, data=None):
    payload = {'plugin': 'SystemdPreferencesApplier', 'message': message}
    if data:
        payload['data'] = data
    log(level, payload)


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).lower() in ('1', 'true', 'yes')


def _expand_windows_var(path, username=None):
    if not path:
        return path
    variables = {
        'HOME': '/etc/skel',
        'HOMEPATH': '/etc/skel',
        'HOMEDRIVE': '/',
        'SystemRoot': '/',
        'SystemDrive': '/',
        'USERNAME': username if username else '',
    }
    if username:
        variables['HOME'] = get_homedir(username)
        variables['HOMEPATH'] = variables['HOME']
    result = path
    for key, value in variables.items():
        replacement = str(value)
        if key not in ('USERNAME',) and not replacement.endswith('/'):
            replacement = '{}{}'.format(replacement, '/')
        result = result.replace('%{}%'.format(key), replacement)
    return result


def _run_command(command):
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    return process.returncode, process.stdout.strip(), process.stderr.strip()


def _read_preferences(storage, scope_name, is_previous=False):
    prefix = 'Software/BaseALT/Policies/Preferences/{}'.format(scope_name)
    if is_previous:
        prefix = 'Previous/{}'.format(prefix)
    key = '{}/Systemds'.format(prefix)
    value = storage.get_entry(key, preg=False)
    if not value:
        return []

    items = string_to_literal_eval(value)
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def _normalize_rule(item):
    unit = item.get('unit')
    state = item.get('state')
    apply_mode = item.get('apply_mode', item.get('applyMode', 'always'))
    policy_target = item.get('policy_target', item.get('policyTarget', 'machine'))
    edit_mode = item.get('edit_mode', item.get('editMode', 'override'))
    uid = item.get('uid')

    if not unit or state not in VALID_STATES:
        return None
    if apply_mode not in VALID_APPLY_MODES:
        return None
    if policy_target not in VALID_POLICY_TARGETS:
        return None
    if edit_mode not in VALID_EDIT_MODES:
        return None
    if not uid:
        return None

    dependencies = item.get('file_dependencies', item.get('fileDependencies', []))
    if not isinstance(dependencies, list):
        dependencies = []
    dependencies = [
        dep for dep in dependencies
        if isinstance(dep, dict)
        and dep.get('mode') in VALID_DEP_MODES
        and dep.get('path')
    ]

    return {
        'uid': str(uid),
        'unit': unit,
        'state': state,
        'now': _as_bool(item.get('now', False)),
        'apply_mode': apply_mode,
        'policy_target': policy_target,
        'edit_mode': edit_mode,
        'dropin_name': item.get('dropin_name', item.get('dropInName', DEFAULT_DROPIN_NAME)) or DEFAULT_DROPIN_NAME,
        'unit_file': item.get('unit_file', item.get('unitFile')),
        'file_dependencies': dependencies,
        'element_type': item.get('element_type', item.get('elementType', 'service')),
    }


def _rule_matches_apply_mode(rule, exists):
    apply_mode = rule['apply_mode']
    if apply_mode == 'always':
        return True
    if apply_mode == 'if_exists':
        return exists
    return not exists


def _is_managed_by_uid(path, uid):
    if not path.exists() or not path.is_file():
        return False
    try:
        content = path.read_text(encoding='utf-8')
    except Exception:
        return False
    return MANAGED_HEADER.format(uid) in content


class _systemd_preferences_runtime:
    def __init__(self, storage, scope_name, context):
        self.storage = storage
        self.scope_name = scope_name
        self.context = context
        self.daemon_reload_required = False
        self.phase2_candidates = []

    def _systemctl(self, *args):
        command = self.context.systemctl_base + list(args)
        return _run_command(command)

    def _exists(self, unit_name):
        rc, stdout, _ = self._systemctl('show', '--property=LoadState', '--value', unit_name)
        if rc != 0:
            return False
        load_state = stdout.strip()
        return load_state not in ('not-found', 'error', '')

    def _daemon_reload(self):
        log('D245', {'context': self.context.mode})
        rc, _, err = self._systemctl('daemon-reload')
        if rc != 0:
            log('W50', {'context': self.context.mode, 'error': err})
            _syslog('W', 'daemon-reload failed', {'context': self.context.mode, 'error': err})
        self.daemon_reload_required = False

    def _active_state(self, unit_name):
        rc, stdout, _ = self._systemctl('show', '--property=ActiveState', '--value', unit_name)
        if rc != 0:
            return None
        return stdout.strip()

    def _restart(self, rule):
        if rule.get('element_type') in NON_RESTARTABLE_TYPES:
            log('W49', {'unit': rule['unit'], 'type': rule.get('element_type')})
            _syslog('D', 'Unit type is non-restartable', {'unit': rule['unit'], 'type': rule.get('element_type')})
            return

        state = self._active_state(rule['unit'])
        if state not in ('active', 'activating'):
            return

        rc, _, err = self._systemctl('restart', rule['unit'])
        if rc != 0:
            _syslog('W', 'Restart failed', {'unit': rule['unit'], 'error': err})

    def _rule_managed_paths(self, rule):
        unit_file_path = Path(self.context.systemd_dir).joinpath(rule['unit'])
        dropin_path = Path(self.context.systemd_dir).joinpath(
            '{}.d'.format(rule['unit']), rule['dropin_name'])
        return unit_file_path, dropin_path

    def _write_rule_file(self, target_file, uid, unit_file):
        target_file.parent.mkdir(parents=True, exist_ok=True)
        marker = MANAGED_HEADER.format(uid)
        body = unit_file if unit_file.endswith('\n') else '{}\n'.format(unit_file)
        content = '{}\n{}'.format(marker, body)
        if target_file.exists():
            try:
                old_content = target_file.read_text(encoding='utf-8')
            except Exception:
                old_content = None
            if old_content == content:
                return
            target_file.write_text(content, encoding='utf-8')
            record_changed(str(target_file))
        else:
            target_file.write_text(content, encoding='utf-8')
            record_presence_changed(str(target_file))
        self.daemon_reload_required = True

    def _apply_edit(self, rule, exists):
        unit_file = rule.get('unit_file')
        if not unit_file:
            return

        unit_file_path, dropin_path = self._rule_managed_paths(rule)
        edit_mode = rule['edit_mode']
        if edit_mode == 'create':
            self._write_rule_file(unit_file_path, rule['uid'], unit_file)
            return
        if edit_mode == 'override':
            self._write_rule_file(dropin_path, rule['uid'], unit_file)
            return
        if exists:
            self._write_rule_file(dropin_path, rule['uid'], unit_file)
        else:
            self._write_rule_file(unit_file_path, rule['uid'], unit_file)

    def _run_state_action(self, rule):
        state = rule['state']
        if state == 'as_is':
            return

        action = state
        command = [action]
        if rule['now']:
            command.append('--now')
        command.append(rule['unit'])
        rc, _, err = self._systemctl(*command)
        if rc == 0:
            return

        if not rule['now']:
            _syslog('W', 'State apply failed', {'unit': rule['unit'], 'state': state, 'error': err})
            return

        # Fallback behavior for systemd variants lacking --now support.
        fallback = [action, rule['unit']]
        rc, _, err = self._systemctl(*fallback)
        if rc != 0:
            _syslog('W', 'State apply failed', {'unit': rule['unit'], 'state': state, 'error': err})
            return

        runtime_action = 'start' if state in ('enable', 'unmask', 'preset') else 'stop'
        self._systemctl(runtime_action, rule['unit'])

    def apply_rules(self, rules):
        for rule in rules:
            log('D244', {'unit': rule['unit'], 'state': rule['state']})
            exists = self._exists(rule['unit'])
            if not _rule_matches_apply_mode(rule, exists):
                continue

            self._apply_edit(rule, exists)
            if self.daemon_reload_required:
                self._daemon_reload()
            self._run_state_action(rule)
            self.phase2_candidates.append(rule)

    def cleanup_removed_rules(self, removed_rules):
        affected_units = set()
        for rule in removed_rules:
            log('D246', {'unit': rule['unit'], 'uid': rule['uid']})
            unit_file_path, dropin_path = self._rule_managed_paths(rule)
            for target in (unit_file_path, dropin_path):
                if not _is_managed_by_uid(target, rule['uid']):
                    continue
                try:
                    target.unlink()
                    record_presence_changed(str(target))
                    self.daemon_reload_required = True
                    affected_units.add(rule['unit'])
                except Exception as exc:
                    _syslog('W', 'Failed to cleanup managed file', {'path': str(target), 'error': str(exc)})
            dropin_dir = dropin_path.parent
            if dropin_dir.exists():
                try:
                    dropin_dir.rmdir()
                except OSError:
                    pass

        if self.daemon_reload_required:
            self._daemon_reload()
            for unit_name in affected_units:
                cleanup_rule = {
                    'unit': unit_name,
                    'element_type': 'service',
                }
                self._restart(cleanup_rule)

    def _dependency_changed(self, dependency, username=None):
        dep_path = _expand_windows_var(dependency['path'], username)
        mode = dependency['mode']
        return query(dep_path, mode=mode)

    def post_restart(self, username=None):
        for rule in self.phase2_candidates:
            dependencies = rule.get('file_dependencies', [])
            if not dependencies:
                continue
            if any(self._dependency_changed(dep, username=username) for dep in dependencies):
                log('D247', {'unit': rule['unit']})
                self._restart(rule)


def _get_removed_rules(storage, scope_name, target):
    current_raw = _read_preferences(storage, scope_name, is_previous=False)
    previous_raw = _read_preferences(storage, scope_name, is_previous=True)
    current_map = {}
    previous_map = {}
    for item in current_raw:
        normalized = _normalize_rule(item)
        if normalized is not None and normalized['policy_target'] == target:
            current_map[normalized['uid']] = normalized
    for item in previous_raw:
        normalized = _normalize_rule(item)
        if normalized is not None and normalized['policy_target'] == target:
            previous_map[normalized['uid']] = normalized
    removed_uids = set(previous_map.keys()) - set(current_map.keys())
    return [previous_map[uid] for uid in removed_uids]


def _get_rules_for_scope(storage, scope_name, target):
    current_raw = _read_preferences(storage, scope_name, is_previous=False)
    rules = []
    for item in current_raw:
        normalized = _normalize_rule(item)
        if normalized is None:
            continue
        if normalized['policy_target'] != target:
            continue
        rules.append(normalized)
    return rules


def _collect_dependency_paths(storage, scope_name, target, username=None):
    dependency_paths = []
    for rule in _get_rules_for_scope(storage, scope_name, target):
        for dependency in rule.get('file_dependencies', []):
            dep_path = _expand_windows_var(dependency.get('path'), username)
            if dep_path:
                dependency_paths.append(dep_path)
    return dependency_paths


class systemd_preferences_applier(applier_frontend):
    __module_name = 'SystemdPreferencesApplier'
    __module_experimental = True
    __module_enabled = False
    __scope_name = 'Machine'

    def __init__(self, storage):
        self.storage = storage
        self.__module_enabled = check_enabled(self.storage, self.__module_name, self.__module_experimental)

    def prime_dependency_journal(self):
        if not self.__module_enabled:
            return
        watch_many(_collect_dependency_paths(self.storage, self.__scope_name, target='machine'))

    def apply(self):
        if not self.__module_enabled:
            log('D243')
            return

        log('D240')
        runtime = _systemd_preferences_runtime(self.storage, self.__scope_name, _Context(mode='machine'))
        rules = _get_rules_for_scope(self.storage, self.__scope_name, target='machine')
        runtime.apply_rules(rules)
        runtime.cleanup_removed_rules(_get_removed_rules(self.storage, self.__scope_name, target='machine'))
        runtime.post_restart()


class systemd_preferences_applier_user(applier_frontend):
    __module_name = 'SystemdPreferencesApplierUser'
    __module_experimental = True
    __module_enabled = False

    def __init__(self, storage, username):
        self.storage = storage
        self.username = username
        self.uid = get_uid_by_username(username)
        self.user_bus_path = '/run/user/{}/bus'.format(self.uid) if self.uid is not None else None
        self.__module_enabled = check_enabled(self.storage, self.__module_name, self.__module_experimental)

    def prime_dependency_journal(self):
        if not self.__module_enabled:
            return

        dependency_paths = []
        dependency_paths.extend(_collect_dependency_paths(self.storage, self.username, target='machine'))
        dependency_paths.extend(_collect_dependency_paths(
            self.storage,
            self.username,
            target='user',
            username=self.username,
        ))
        watch_many(dependency_paths)

    def admin_context_apply(self):
        if not self.__module_enabled:
            log('D243')
            return

        log('D241', {'username': self.username})
        runtime = _systemd_preferences_runtime(self.storage, self.username, _Context(mode='machine'))
        rules = _get_rules_for_scope(self.storage, self.username, target='machine')
        runtime.apply_rules(rules)
        runtime.cleanup_removed_rules(_get_removed_rules(self.storage, self.username, target='machine'))
        runtime.post_restart()

    def user_context_apply(self):
        if not self.__module_enabled:
            log('D243')
            return
        log('D242', {'username': self.username})
        if not self.user_bus_path or not os.path.exists(self.user_bus_path):
            log('W48', {'username': self.username, 'path': self.user_bus_path})
            _syslog('W', 'systemd --user manager is unavailable', {
                'username': self.username,
                'path': self.user_bus_path,
            })
            return

        runtime = _systemd_preferences_runtime(
            self.storage,
            self.username,
            _Context(mode='user', username=self.username))
        rules = _get_rules_for_scope(self.storage, self.username, target='user')
        runtime.apply_rules(rules)
        runtime.cleanup_removed_rules(_get_removed_rules(self.storage, self.username, target='user'))
        runtime.post_restart(username=self.username)
