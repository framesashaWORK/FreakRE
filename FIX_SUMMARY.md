# FreakRE Fixes Applied

## 1. Cache Eviction (UI State Bottleneck)

**Problem:** `decompile_cache`, `cfg_cache`, and `xref_view_cache` used `.clear()` when exceeding capacity, discarding ALL entries including the currently-viewed function. On large binaries this caused constant re-decompilation storms.

**Fix:** Replaced with distance-based eviction via `evict_cache_by_distance()`:
- `decompile_cache`: evicts to 128 entries, keeping those closest to current cursor
- `cfg_cache`: evicts to 32 entries by distance  
- `xref_view_cache`: drops oldest half when over 256

**Files changed:** `desktop-ui/src/app.rs`

---

## 2. Symbol Integration (PDB/DWARF)

**Problem:** `freakre-symbols` crate existed but was not wired into the UI at all.

**Fix:**
- Added `freakre-symbols` dependency to `desktop-ui/Cargo.toml`
- Added `symbol_db: Option<SymbolDb>` field to `FreakREApp`
- Auto-loads symbols after scan completes (`try_load_symbols()`):
  - First tries PDB file alongside binary (`.pdb` extension)
  - Falls back to DWARF from ELF bytes
- `current_function_name_at()` now checks symbol DB before scanner heuristics
- Symbol DB cleared on file change in `reset_per_file_analysis_state()`
- Toast notifications on successful symbol load

**Files changed:** `desktop-ui/Cargo.toml`, `desktop-ui/src/app.rs`
