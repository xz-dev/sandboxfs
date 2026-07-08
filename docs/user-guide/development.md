# Development checks

Run formatting, tests, and lint checks before submitting changes:

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

FUSE behavior tests require `/dev/fuse` and `fusermount3` support:

```sh
SANDBOXFS_RUN_FUSE_TESTS=1 cargo test --test fuse_behavior -- --ignored
```

Stress tests are opt-in:

```sh
SANDBOXFS_RUN_FUSE_TESTS=1 SANDBOXFS_RUN_STRESS_TESTS=1 cargo test --test fuse_behavior stress_multiple_pending_viewers_do_not_consume_request -- --ignored
```
