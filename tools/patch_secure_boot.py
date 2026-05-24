"""Apply the 7.1(c) A.ii change to the PX4 fork: log a PARAM_CHANGE/SUCCESS
audit entry when a manufacturer-signed firmware update changes the certified
flight parameters (data_hash of the .compliance_params partition).

Run inside WSL:  python3 /mnt/d/Projects/Drone/tools/patch_secure_boot.py
Idempotent — re-running is a no-op once applied.
"""
import os
import sys

FORK = os.path.expanduser('~/PX4-Autopilot')
SB = os.path.join(FORK, 'src/modules/secure_boot')


def patch(path, edits):
    full = os.path.join(SB, path)
    with open(full, 'r', encoding='utf-8') as f:
        text = f.read()
    orig = text
    for old, new, marker in edits:
        if marker in text:
            print(f'  [skip] {path}: already applied ({marker!r})')
            continue
        n = text.count(old)
        if n != 1:
            print(f'  [FAIL] {path}: anchor found {n}x (expected 1): {old[:60]!r}')
            sys.exit(1)
        text = text.replace(old, new)
        print(f'  [ok]   {path}: applied ({marker!r})')
    if text != orig:
        with open(full, 'w', encoding='utf-8') as f:
            f.write(text)


print(f'Patching fork at {FORK}')

# 1) Gatekeeper header — expose verified staged manifest
patch('FirmwareUpdateGatekeeper.hpp', [(
    '\tstatic bool verifyAndAuthorize();',
    '\tstatic bool verifyAndAuthorize(security_manifest_t *out_manifest = nullptr);',
    'out_manifest = nullptr',
)])

# 2) Gatekeeper impl — accept out-param and copy verified manifest on success
patch('FirmwareUpdateGatekeeper.cpp', [
    (
        'bool FirmwareUpdateGatekeeper::verifyAndAuthorize()',
        'bool FirmwareUpdateGatekeeper::verifyAndAuthorize(security_manifest_t *out_manifest)',
        'verifyAndAuthorize(security_manifest_t *out_manifest)',
    ),
    (
        '\tmemcpy(auth.firmware_version, manifest.version, 32);',
        '\tmemcpy(auth.firmware_version, manifest.version, 32);\n'
        '\n'
        '\t/* 7.1(c): expose the verified staged manifest so the caller can detect\n'
        '\t * whether the certified flight parameters (data_hash) changed. */\n'
        '\tif (out_manifest) {\n'
        '\t\t*out_manifest = manifest;\n'
        '\t}',
        '*out_manifest = manifest;',
    ),
])

# 3) Module main — include + diff data_hash + log PARAM_CHANGE/SUCCESS
patch('secure_boot_main.cpp', [
    (
        '#include "ComplianceParamGuard.hpp"',
        '#include "ComplianceParamGuard.hpp"\n#include "SecureStorageManager.hpp"',
        '#include "SecureStorageManager.hpp"',
    ),
    (
        '\t\tbool authorized = FirmwareUpdateGatekeeper::verifyAndAuthorize();',
        '\t\tsecurity_manifest_t staged{};\n'
        '\t\tbool authorized = FirmwareUpdateGatekeeper::verifyAndAuthorize(&staged);',
        'verifyAndAuthorize(&staged)',
    ),
    (
        "\t\t/* Audit event delivery is asynchronous (see comment in 'start'). */\n"
        "\n"
        "\t\treturn authorized ? 0 : 1;",
        "\t\t/* Audit event delivery is asynchronous (see comment in 'start'). */\n"
        "\n"
        "\t\t/* 7.1(c) A.ii: a signed update that changes the certified flight\n"
        "\t\t * parameters changes data_hash (SHA-256 of the .compliance_params\n"
        "\t\t * partition). Record the change in the audit log. */\n"
        "\t\tif (authorized) {\n"
        "\t\t\tsecurity_manifest_t active{};\n"
        "\n"
        "\t\t\tif (SecureStorageManager::load(active) &&\n"
        "\t\t\t    memcmp(active.data_hash, staged.data_hash, SECURITY_MANIFEST_HASH_LEN) != 0) {\n"
        "\t\t\t\tpublish_audit_event(\n"
        "\t\t\t\t\tsecurity_audit_event_s::EVENT_PARAM_CHANGE,\n"
        "\t\t\t\t\tsecurity_audit_event_s::RESULT_SUCCESS,\n"
        "\t\t\t\t\t0, \"FW update changed flight params\");\n"
        "\t\t\t\tPX4_INFO(\"secure_boot: signed firmware update changed \"\n"
        "\t\t\t\t\t \"flight parameters (data_hash changed)\");\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\n"
        "\t\treturn authorized ? 0 : 1;",
        'EVENT_PARAM_CHANGE,\n\t\t\t\t\tsecurity_audit_event_s::RESULT_SUCCESS',
    ),
])

print('Done.')
