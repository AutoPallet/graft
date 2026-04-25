#!/usr/bin/env bash
# M1.h: measure pageflash churn (pages-changed / bytes / wall time) for
# a fixed set of edits, both via stock-rustc and via GRAFT=overlay.
# Run inside the container (docker exec graft-esp32s3 bash scripts/m1h_churn.sh).
#
# Edits exercised (defined inline below):
#   1. same-length string edit (Hello → Howdy)
#   2. length-extending string edit (Hello → Hello!!!)
#   3. new local fn + call (graft_entry now calls a new helper)
#   4. tick increment delta change (1 → 2; tiny bytecode shift)
#
# Prereqs: /tmp/m1h_baseline.txt  doesn't have to pre-exist; this script
# overwrites results.
set -euo pipefail

cd /workspace/esp32s3-hello
SRC=src/main.rs
OUT=/tmp/m1h_results.tsv
ELF=target/xtensa-esp32s3-none-elf/release/esp32s3-hello

# Snapshot the baseline source so we can restore between scenarios.
cp $SRC /tmp/main.rs.original
trap 'cp /tmp/main.rs.original $SRC' EXIT

build_stock() {
    local out=$1
    cp /tmp/main.rs.original $SRC
    touch $SRC
    GRAFT= GRAFT_ENTRY_SYMBOL= cargo build --release > /dev/null 2>&1
    espflash save-image --chip esp32s3 $ELF $out > /dev/null
}

build_graft_base() {
    cp /tmp/main.rs.original $SRC
    touch $SRC
    GRAFT=base GRAFT_ENTRY_SYMBOL=graft_entry cargo build --release > /dev/null 2>&1
    cp $ELF /tmp/m1h_base.elf
    espflash save-image --chip esp32s3 $ELF /tmp/m1h_base.img > /dev/null
}

apply_edit() {
    local name=$1
    case "$name" in
        same_len_string)
            sed -i 's/Hello from/Howdy from/' $SRC ;;
        longer_string)
            sed -i 's/Hello from ESP32-S3!/Hello from ESP32-S3 v2!!/' $SRC ;;
        new_helper)
            # Inject a brand-new no_mangle helper that graft_entry calls,
            # plus the call site.
            python3 - <<'PY'
import re, pathlib
p = pathlib.Path("/workspace/esp32s3-hello/src/main.rs")
s = p.read_text()
# Inject a helper before #[unsafe(no_mangle)]
helper = """
#[inline(never)]
fn brand_new_helper() -> u32 {
    1234
}
"""
s = s.replace("#[unsafe(no_mangle)]", helper + "#[unsafe(no_mangle)]", 1)
# Add a call to it in the loop.
s = s.replace(
    'tick = tick.wrapping_add(1);',
    'tick = tick.wrapping_add(brand_new_helper());'
)
p.write_text(s)
PY
            ;;
        tick_delta)
            sed -i 's/wrapping_add(1)/wrapping_add(2)/' $SRC ;;
        *) echo "unknown edit $name" >&2; exit 1 ;;
    esac
    touch $SRC
}

build_stock_new() {
    local out=$1
    GRAFT= GRAFT_ENTRY_SYMBOL= cargo build --release > /dev/null 2>&1
    espflash save-image --chip esp32s3 $ELF $out > /dev/null
}

build_graft_new() {
    local out=$1
    GRAFT=overlay GRAFT_BASE_ELF=/tmp/m1h_base.elf GRAFT_ENTRY_SYMBOL=graft_entry \
        cargo build --release > /dev/null 2>&1
    espflash save-image --chip esp32s3 $ELF $out > /dev/null
}

dry_pageflash() {
    local base=$1
    local new=$2
    local label=$3
    local total bytes pages run_count base_size new_size
    base_size=$(stat -c %s "$base")
    new_size=$(stat -c %s "$new")
    local report
    report=$(python3 /workspace/scripts/pageflash.py "$base" "$new" --dry-run 2>&1)
    # Parse:
    #   "img: NN bytes / TT pages"
    #   "diff: P/T pages (X.X%), B bytes in R run(s)"
    pages=$(echo "$report" | awk '/^diff:/ {gsub("[/,]"," "); print $2}')
    total=$(echo "$report" | awk '/^diff:/ {gsub("[/,]"," "); print $3}')
    bytes=$(echo "$report" | awk '/^diff:/ {gsub(",",""); for(i=1;i<=NF;i++) if($i=="bytes") print $(i-1)}')
    run_count=$(echo "$report" | awk '/^diff:/ {gsub(",",""); for(i=1;i<=NF;i++) if($i=="in") print $(i+1)}')
    printf "%s\t%s\t%d\t%d\t%s\t%s\t%s\n" \
        "$label" "$base_size→$new_size" "$pages" "$total" "$bytes" "$run_count" "$report" | head -1
}

scenarios=(same_len_string longer_string new_helper tick_delta)

echo -e "scenario\tmode\timg_sz\tpages_changed\tpages_total\tbytes_changed\truns" > $OUT

# Build a stock baseline once.
echo "[1/3] stock baseline build" >&2
build_stock /tmp/m1h_stock_base.img

# Build a graft base once.
echo "[2/3] graft base build" >&2
build_graft_base

echo "[3/3] running ${#scenarios[@]} scenarios..." >&2
for s in "${scenarios[@]}"; do
    echo "  scenario: $s (stock)" >&2
    cp /tmp/main.rs.original $SRC
    apply_edit "$s"
    build_stock_new /tmp/m1h_stock_new.img
    dry_pageflash /tmp/m1h_stock_base.img /tmp/m1h_stock_new.img "$s	stock" >> $OUT

    echo "  scenario: $s (graft)" >&2
    cp /tmp/main.rs.original $SRC
    apply_edit "$s"
    build_graft_new /tmp/m1h_graft_new.img
    dry_pageflash /tmp/m1h_base.img /tmp/m1h_graft_new.img "$s	graft" >> $OUT
done

echo "" >&2
echo "===== results =====" >&2
column -t -s$'\t' $OUT
