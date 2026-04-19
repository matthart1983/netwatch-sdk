# Publishing

Releasing a new version of `netwatch-sdk` is three steps: bump the version, tag, push. Crates.io publishing is currently **manual** — there's no Release workflow on this repo. (If you want to automate it, copy the pattern from [`netwatch`](https://github.com/matthart1983/netwatch/blob/main/.github/workflows/release.yml) or [`netscan`](https://github.com/matthart1983/netscan/blob/main/.github/workflows/release.yml).)

## Version bumping

Pre-1.0, semver under SDK rules:

| Change                                                           | Bump  | Example         |
| ---------------------------------------------------------------- | ----- | --------------- |
| Bug fix, doc-only, internal refactor                             | patch | `0.1.0 → 0.1.1` |
| Additive: new `Option<…>` field, new collector, new free function | minor | `0.1.1 → 0.2.0` |
| Breaking: required field, removed function, renamed enum variant | major | `0.2.0 → 1.0.0` |

After 1.0 you'd switch to standard semver and treat any wire-format change as breaking.

## Release checklist

1. **Make sure `cargo test` passes locally** on the platform you're cutting from. CI on the merge commit also has to be green.
2. **Bump `version` in `Cargo.toml`.**
3. **Update `Cargo.lock`** by running `cargo build` once.
4. **Commit:**

   ```sh
   git add Cargo.toml Cargo.lock
   git commit -m "v0.X.Y: <one-liner summary of what changed>"
   git push
   ```

5. **Tag and push the tag:**

   ```sh
   git tag v0.X.Y
   git push origin v0.X.Y
   ```

6. **Publish to crates.io:**

   ```sh
   cargo publish
   ```

   The first `cargo publish` from a new shell asks for the token; `cargo login` once with a token from <https://crates.io/me> and you won't be prompted again.

7. **Announce coordinated upgrades.** Both [`netwatch-agent`](https://github.com/matthart1983/netwatch-agent) and `netwatch-cloud` depend on this crate. Bump them in the same window:

   ```sh
   # in each consumer:
   cargo update -p netwatch-sdk
   cargo build      # confirm the new SDK compiles in the consumer
   cargo test
   ```

   For breaking changes, plan the bump as a PR pair (agent + cloud) merged within minutes of each other so there's no production window where the agent talks an SDK version the cloud can't decode.

## Automating it later

If/when manual gets tedious, the simplest workflow:

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags: ['v*']
permissions: { contents: write }
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Publish to crates.io
        run: cargo publish
        env:
          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
```

Set the secret with `gh secret set CARGO_REGISTRY_TOKEN --repo matthart1983/netwatch-sdk` and from then on `git push origin vX.Y.Z` is the whole release.

## Yanking a bad release

If a published version turns out to be broken:

```sh
cargo yank --vers X.Y.Z
```

Yanking doesn't delete the version (that's not allowed on crates.io after 72 h), but it prevents new dependents from resolving to it. Existing `Cargo.lock` files keep working. Always release a fixed `X.Y.(Z+1)` immediately after yanking — leaving downstream users with no advance path is worse than the bug you yanked.
