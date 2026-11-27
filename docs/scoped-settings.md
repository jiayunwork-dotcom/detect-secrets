# Scoped settings and concurrency

## Problem

`detect_secrets` used a single process-wide `Settings` object. `transient_settings`
mutated that object in place:

```python
original = get_settings().json()
cache_bust()
try:
    yield configure_settings_from_baseline(config)
finally:
    cache_bust()
    configure_settings_from_baseline(original)
```

Everything downstream read from that one object through module-level
`lru_cache`s: plugin instances (`get_plugins`), filter functions (`get_filters`),
compiled regexes (`filters.regex`), the word-list automaton (`filters.wordlist`),
the gibberish model, the baseline filename and the verification policy.

Two concurrent scans therefore shared one configuration. A scan that entered a
temporary configuration while another was running would overwrite it, causing
false negatives (a detector quietly disappeared) and a corrupted serialized
policy (the baseline recorded the wrong `plugins_used` / `filters_used`).

## Design

Configuration is scoped to the *execution context* instead of the process.

| Concern | Mechanism |
| --- | --- |
| Where the config lives | `contextvars.ContextVar`, so it is per-thread and per-asyncio-task |
| Entering a scope | `transient_settings` installs a **new** `Settings`, restores the previous binding in `finally` |
| Inheritance | a second `ContextVar` holds an immutable `FrozenSettings` **snapshot**; tasks copy it at creation |
| Mutation isolation | mutating a scope publishes a **new** snapshot into that context only (copy-on-write) |
| Cache correctness | each `Settings` owns its plugin/filter/derived caches; config change replaces the owner |

### What is isolated vs. shared

**Isolated (per `Settings` object, therefore per scope):**

* The plugin configuration mapping (`Settings.plugins`).
* The filter configuration mapping (`Settings.filters`).
* Initialized plugin instances (`Settings.get_plugins`).
* The active filter function list (`Settings.get_filters`).
* Derived filter values that depend on configuration: compiled regex lists,
  word-list automaton handles, the baseline filename, the verification policy.

These are the things whose *value* depends on the configuration, so sharing
them is exactly what caused the bug. Keeping them on the settings object makes
"change the config" and "change the behaviour and the recorded policy"
inseparable: they invalidate together through `_InvalidatingDict`'s change
notifications.

**Safely shared (process-wide, content-keyed):**

* Built-in plugin classes (`get_builtin_mapping`) -- immutable code.
* Compiled regex objects keyed by `(path, pattern tuple)` -- `re.compile` results
  are immutable and fully determined by the pattern.
* Word-list automatons keyed by `(filename, min_length)` -- derived purely from
  those inputs.
* The gibberish model keyed by model path -- loaded once and only read
  afterwards.

For these, the cache key *is* the artifact's identity, so two scopes with the
same inputs can share the result without any risk of contamination. That keeps
the cost of "a new scope" low: only the cheap configuration-derived wrapper is
rebuilt, not the expensive parsers.

### Copy overhead vs. cache invalidation

Two extremes were available:

1. **Deep-copy the whole configuration on every scope entry.** Simple, but pays a
   full deep copy of the plugin/filter maps per scope, and still leaves shared
   `lru_cache`s holding stale derived artifacts unless they are globally cleared
   -- which itself would break concurrent scopes.
2. **Keep the global object and clear every cache on each transition.** This is
   the old behaviour with extra locking; it is fundamentally unable to keep two
   concurrent scans correct, because clearing a cache is global.

The chosen design is a middle point: a new `Settings` object per scope (cheap --
two small dicts), with derived artifacts memoized on that object and published
into an immutable snapshot only when configuration actually changes. Expensive
pure artefacts are reused across scopes via content keys. This makes scope entry
O(config size) instead of O(model size), keeps concurrent scopes correct, and
keeps serialization honest because it reads the same object the filters do.

### The snapshot / copy-on-write detail

A `ContextVar` copies the *reference* into a new task, not the value. To honour
"a task inherits the configuration at creation, and later edits on either side do
not interfere", the binding also records the *execution identity* (thread id +
current task id). When `get_settings()` is called:

* same identity as the binding -> return the existing object (the hot path);
* different identity (a task that inherited a parent's binding) -> materialize a
  fresh `Settings` from the inherited snapshot, bind it to *this* context, and
  return it.

Mutating a bound `Settings` republishes its snapshot into the current context
only. Because contexts are copies, sibling tasks and the parent never observe
each other's edits.

## Boundaries that guarantee the requirements

* **Threads** get empty contexts, so they never inherit a neighbour's transient
  scope, and cannot read or write it.
* **Tasks** inherit the snapshot present at `asyncio.create_task` time, then
  diverge on first mutation.
* **Nesting** is stack-like: `transient_settings` saves and restores bindings,
  so normal exit, exceptions and `CancelledError` all restore the enclosing
  configuration. A scope that finishes cannot touch another live scope's object.
* **Non-scoped** calls keep using one global `Settings` (`_GLOBAL_SETTINGS`),
  preserving the old single-threaded behaviour and the existing
  `get_settings().configure_*` / `parse_args` flows.
