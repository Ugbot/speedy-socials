# contributing

## before committing

```sh
just fmt
```

or without just:

```sh
zig fmt .
```

CI runs `zig fmt --check .` and will fail on unformatted code.
