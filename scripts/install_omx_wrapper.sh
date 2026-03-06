#!/usr/bin/env bash
set -euo pipefail

target_dir="${HOME}/.local/bin"
target_path="${target_dir}/omx"
target_resolved="$(readlink -f "${target_path}")"

resolve_real_omx() {
    while IFS= read -r candidate; do
        [[ -n "${candidate}" ]] || continue
        local resolved
        resolved="$(readlink -f "${candidate}")"
        [[ "${resolved}" == "${target_resolved}" ]] && continue
        printf '%s\n' "${resolved}"
        return 0
    done < <(type -a -p omx 2>/dev/null || true)
    return 1
}

real_omx="$(resolve_real_omx || true)"
if [[ -z "${real_omx}" ]]; then
    echo "install_omx_wrapper: could not locate the real 'omx' binary in PATH" >&2
    exit 1
fi

mkdir -p "${target_dir}"

cat > "${target_path}" <<EOF
#!/usr/bin/env bash
set -euo pipefail

SELF="\$(readlink -f "\$0")"
FALLBACK_REAL_OMX="${real_omx}"

detect_project_root() {
    local dir="\${PWD}"
    while [[ "\${dir}" != "/" ]]; do
        if [[ -f "\${dir}/tools/coordination_cli.py" && -f "\${dir}/.omx/hooks/coord-session-start.mjs" ]]; then
            printf '%s\n' "\${dir}"
            return 0
        fi
        dir="\$(dirname "\${dir}")"
    done
    return 1
}

find_real_omx() {
    while IFS= read -r candidate; do
        [[ -n "\${candidate}" ]] || continue
        local resolved
        resolved="\$(readlink -f "\${candidate}")"
        [[ "\${resolved}" == "\${SELF}" ]] && continue
        printf '%s\n' "\${resolved}"
        return 0
    done < <(type -a -p omx 2>/dev/null || true)

    if [[ -n "\${FALLBACK_REAL_OMX}" && -x "\${FALLBACK_REAL_OMX}" ]]; then
        printf '%s\n' "\${FALLBACK_REAL_OMX}"
        return 0
    fi

    return 1
}

if [[ -z "\${COORD_PROJECT_ROOT:-}" ]]; then
    if project_root="\$(detect_project_root)"; then
        export COORD_PROJECT_ROOT="\${project_root}"
    fi
fi

if [[ -z "\${OMX_HOOK_PLUGINS:-}" && -n "\${COORD_PROJECT_ROOT:-}" ]]; then
    export OMX_HOOK_PLUGINS=1
fi

real_omx="\$(find_real_omx || true)"
if [[ -z "\${real_omx}" ]]; then
    echo "omx wrapper: could not locate the real OMX binary" >&2
    exit 127
fi

exec "\${real_omx}" "\$@"
EOF

chmod +x "${target_path}"

if [[ ":${PATH}:" != *":${target_dir}:"* ]]; then
    echo "Installed wrapper to ${target_path}, but ${target_dir} is not currently in PATH." >&2
    echo "Add the following to your shell profile:" >&2
    echo "  export PATH=\"${target_dir}:\$PATH\"" >&2
else
    echo "Installed OMX wrapper: ${target_path}"
fi

echo "Real OMX binary: ${real_omx}"
echo "In coordination-enabled repos, plain 'omx' now auto-enables hook plugins."
