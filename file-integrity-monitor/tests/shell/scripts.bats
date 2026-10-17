#!/usr/bin/env bats
# Shell tests for scripts/*.sh. Run: bats tests/shell
# Everything happens in BATS_TEST_TMPDIR; nothing touches real system paths.

setup() {
    REPO="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
    export REPO
    # shellcheck source=/dev/null
    source "$REPO/scripts/lib/common.sh"
    if [[ -x "$REPO/.venv/bin/fim" ]]; then
        export PATH="$REPO/.venv/bin:$PATH"
    fi
}

# ---------------------------------------------------------------- common.sh
@test "detect_family: ubuntu and debian are debian-family" {
    run detect_family "$REPO/tests/fixtures/os-release/ubuntu"
    [ "$output" = "debian" ]
    run detect_family "$REPO/tests/fixtures/os-release/debian"
    [ "$output" = "debian" ]
}

@test "detect_family: rocky and rhel are rhel-family" {
    run detect_family "$REPO/tests/fixtures/os-release/rocky"
    [ "$output" = "rhel" ]
    run detect_family "$REPO/tests/fixtures/os-release/rhel"
    [ "$output" = "rhel" ]
}

@test "detect_family: unsupported and missing files are unknown" {
    run detect_family "$REPO/tests/fixtures/os-release/alpine"
    [ "$output" = "unknown" ]
    run detect_family "$BATS_TEST_TMPDIR/does-not-exist"
    [ "$output" = "unknown" ]
}

@test "detect_family never executes os-release content" {
    rm -f /tmp/fim-pwned
    run detect_family "$REPO/tests/fixtures/os-release/hostile"
    [ ! -e /tmp/fim-pwned ]
}

@test "safe_remove_tree refuses dangerous targets" {
    run safe_remove_tree "/" .m
    [ "$status" -ne 0 ]
    run safe_remove_tree "relative/dir" .m
    [ "$status" -ne 0 ]
    run safe_remove_tree "/tmp" .m
    [ "$status" -ne 0 ]
    mkdir "$BATS_TEST_TMPDIR/nomarker"
    run safe_remove_tree "$BATS_TEST_TMPDIR/nomarker" .m
    [ "$status" -ne 0 ]
    [ -d "$BATS_TEST_TMPDIR/nomarker" ]
}

@test "safe_remove_tree refuses symlinks and wrong marker content" {
    mkdir -p "$BATS_TEST_TMPDIR/real/sub"
    echo right > "$BATS_TEST_TMPDIR/real/.m"
    ln -s "$BATS_TEST_TMPDIR/real" "$BATS_TEST_TMPDIR/link"
    run safe_remove_tree "$BATS_TEST_TMPDIR/link" .m
    [ "$status" -ne 0 ]
    run safe_remove_tree "$BATS_TEST_TMPDIR/real" .m wrong
    [ "$status" -ne 0 ]
    [ -d "$BATS_TEST_TMPDIR/real/sub" ]
    run safe_remove_tree "$BATS_TEST_TMPDIR/real" .m right
    [ "$status" -eq 0 ]
    [ ! -e "$BATS_TEST_TMPDIR/real" ]
}

# ---------------------------------------------------------------- install.sh
@test "install.sh --help documents options" {
    run "$REPO/scripts/install.sh" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"--dry-run"* && "$output" == *"--with-systemd"* ]]
}

@test "install.sh rejects unknown options and relative paths" {
    run "$REPO/scripts/install.sh" --bogus
    [ "$status" -eq 2 ]
    run "$REPO/scripts/install.sh" --dry-run --prefix relative/path
    [ "$status" -eq 2 ]
    run "$REPO/scripts/install.sh" --dry-run --prefix "/tmp/a/../b"
    [ "$status" -eq 2 ]
    run "$REPO/scripts/install.sh" --prefix
    [ "$status" -eq 2 ]
}

@test "install.sh --dry-run changes nothing and shows the plan" {
    P="$BATS_TEST_TMPDIR/inst"
    run "$REPO/scripts/install.sh" --dry-run --with-systemd \
        --prefix "$P/venv" --bin-dir "$P/bin" --etc-dir "$P/etc" --state-dir "$P/state" --systemd-dir "$P/sd"
    [ "$status" -eq 0 ]
    [[ "$output" == *"-m venv $P/venv"* ]]
    [[ "$output" == *"--require-hashes -r $REPO/requirements.lock"* ]]
    [[ "$output" == *"Dry run complete"* ]]
    [ ! -e "$P" ]
}

@test "install.sh refuses a non-empty prefix it did not create" {
    mkdir -p "$BATS_TEST_TMPDIR/foreign"
    echo precious > "$BATS_TEST_TMPDIR/foreign/data"
    run "$REPO/scripts/install.sh" --prefix "$BATS_TEST_TMPDIR/foreign" --bin-dir "$BATS_TEST_TMPDIR/b" \
        --etc-dir "$BATS_TEST_TMPDIR/e" --state-dir "$BATS_TEST_TMPDIR/s"
    [ "$status" -eq 3 ]
    [ "$(cat "$BATS_TEST_TMPDIR/foreign/data")" = "precious" ]
}

# ---------------------------------------------------------------- uninstall.sh
@test "uninstall.sh only removes prefixes carrying the installer marker" {
    mkdir -p "$BATS_TEST_TMPDIR/pfx/bin" "$BATS_TEST_TMPDIR/bin"
    run "$REPO/scripts/uninstall.sh" --prefix "$BATS_TEST_TMPDIR/pfx" --bin-dir "$BATS_TEST_TMPDIR/bin"
    [ "$status" -eq 3 ]
    [ -d "$BATS_TEST_TMPDIR/pfx" ]
    echo fim-install > "$BATS_TEST_TMPDIR/pfx/.fim-install"
    ln -s "$BATS_TEST_TMPDIR/pfx/bin/fim" "$BATS_TEST_TMPDIR/bin/fim"
    run "$REPO/scripts/uninstall.sh" --prefix "$BATS_TEST_TMPDIR/pfx" --bin-dir "$BATS_TEST_TMPDIR/bin"
    [ "$status" -eq 0 ]
    [ ! -e "$BATS_TEST_TMPDIR/pfx" ]
    [ ! -L "$BATS_TEST_TMPDIR/bin/fim" ]
}

@test "uninstall.sh leaves a link that points elsewhere" {
    mkdir -p "$BATS_TEST_TMPDIR/bin"
    ln -s /usr/bin/true "$BATS_TEST_TMPDIR/bin/fim"
    run "$REPO/scripts/uninstall.sh" --prefix "$BATS_TEST_TMPDIR/none" --bin-dir "$BATS_TEST_TMPDIR/bin"
    [ -L "$BATS_TEST_TMPDIR/bin/fim" ]
}

# ---------------------------------------------------------------- demo.sh
@test "demo.sh runs, exports reports, and cleans up only its own workspace" {
    command -v fim >/dev/null || skip "fim is not installed in this environment"
    export TMPDIR="$BATS_TEST_TMPDIR/tmp"
    mkdir -p "$TMPDIR"
    echo "unrelated" > "$TMPDIR/keep-me.txt"
    mkdir "$TMPDIR/fim-demo.other"
    echo "other demo" > "$TMPDIR/fim-demo.other/file"
    run "$REPO/scripts/demo.sh" --export "$BATS_TEST_TMPDIR/out"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Demo finished successfully"* ]]
    [[ "$output" == *"Cleaned up"* ]]
    [ -f "$BATS_TEST_TMPDIR/out/report.json" ]
    [ -f "$BATS_TEST_TMPDIR/out/report.csv" ]
    [ "$(cat "$TMPDIR/keep-me.txt")" = "unrelated" ]
    [ "$(cat "$TMPDIR/fim-demo.other/file")" = "other demo" ]
    [ "$(find "$TMPDIR" -maxdepth 1 -name 'fim-demo.*' | wc -l)" -eq 1 ]
}

@test "demo.sh is repeatable" {
    command -v fim >/dev/null || skip "fim is not installed in this environment"
    export TMPDIR="$BATS_TEST_TMPDIR/tmp"
    mkdir -p "$TMPDIR"
    run "$REPO/scripts/demo.sh"
    [ "$status" -eq 0 ]
    run "$REPO/scripts/demo.sh"
    [ "$status" -eq 0 ]
}

@test "demo.sh --keep preserves the workspace and refuses to overwrite --export" {
    command -v fim >/dev/null || skip "fim is not installed in this environment"
    export TMPDIR="$BATS_TEST_TMPDIR/tmp"
    mkdir -p "$TMPDIR" "$BATS_TEST_TMPDIR/exists"
    run "$REPO/scripts/demo.sh" --export "$BATS_TEST_TMPDIR/exists"
    [ "$status" -eq 2 ]
    run "$REPO/scripts/demo.sh" --keep
    [ "$status" -eq 0 ]
    [ "$(find "$TMPDIR" -maxdepth 1 -name 'fim-demo.*' | wc -l)" -eq 1 ]
}

@test "demo.sh never touches paths outside its workspace (strace-free check: config roots)" {
    command -v fim >/dev/null || skip "fim is not installed in this environment"
    export TMPDIR="$BATS_TEST_TMPDIR/tmp"
    mkdir -p "$TMPDIR"
    run "$REPO/scripts/demo.sh" --keep
    ws="$(find "$TMPDIR" -maxdepth 1 -name 'fim-demo.*' | head -n1)"
    run grep -E '^(roots|dir) = ' "$ws/fim.toml"
    [[ "$output" == *"$ws/target"* && "$output" == *"$ws/state"* ]]
    [[ "$output" != *'"/etc'* && "$output" != *'"/usr'* ]]
}

# ---------------------------------------------------------------- run-scan.sh
@test "run-scan.sh writes private reports and propagates the exit code" {
    command -v fim >/dev/null || skip "fim is not installed in this environment"
    W="$BATS_TEST_TMPDIR/w"
    mkdir -p "$W/target" "$W/state"
    echo one > "$W/target/f"
    printf '[baseline]\ndir="%s/state/b"\n[scan]\nroots=["%s/target"]\n' "$W" "$W" > "$W/fim.toml"
    fim -c "$W/fim.toml" baseline create >/dev/null
    export FIM_CONFIG="$W/fim.toml" REPORT_DIR="$W/reports"
    run "$REPO/scripts/run-scan.sh"
    [ "$status" -eq 0 ]
    echo two > "$W/target/f"
    run "$REPO/scripts/run-scan.sh"
    [ "$status" -eq 1 ]
    [ "$(find "$W/reports" -name 'scan-*.json' | wc -l)" -eq 2 ]
    [ "$(stat -c %a "$W/reports")" = "700" ]
    [ "$(stat -c %a "$(find "$W/reports" -name 'scan-*.json' | head -n1)")" = "600" ]
}

@test "run-scan.sh back-to-back runs in the same second do not collide" {
    command -v fim >/dev/null || skip "fim is not installed in this environment"
    W="$BATS_TEST_TMPDIR/w2"
    mkdir -p "$W/target" "$W/state"
    echo one > "$W/target/f"
    printf '[baseline]\ndir="%s/state/b"\n[scan]\nroots=["%s/target"]\n' "$W" "$W" > "$W/fim.toml"
    fim -c "$W/fim.toml" baseline create >/dev/null
    export FIM_CONFIG="$W/fim.toml" REPORT_DIR="$W/reports"
    for _ in 1 2 3 4 5; do
        run "$REPO/scripts/run-scan.sh"
        [ "$status" -eq 0 ]
    done
    [ "$(find "$W/reports" -name 'scan-*.json' | wc -l)" -eq 5 ]
}

@test "run-scan.sh rejects a relative REPORT_DIR" {
    REPORT_DIR=relative run "$REPO/scripts/run-scan.sh"
    [ "$status" -eq 2 ]
}

@test "all scripts are ShellCheck clean" {
    command -v shellcheck >/dev/null || skip "shellcheck not installed"
    cd "$REPO/scripts"
    run shellcheck -x -P SCRIPTDIR ./*.sh lib/*.sh
    [ "$status" -eq 0 ]
}
