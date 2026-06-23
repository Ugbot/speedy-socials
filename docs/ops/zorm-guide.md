# zorm — usage guide

zorm is the in-tree comptime ORM + messaging library
(`zorm/src/zorm.zig`). You declare an entity struct **once** using zorm field
types; zorm generates its table DDL, CRUD SQL, change tracking, relations, a
wire codec, and a schema descriptor at compile time — no runtime reflection.

**Standalone / extractable.** zorm depends on nothing from the host
application (`zorm.zig:8-10`). The host bridges its storage/stream/queue
backends to zorm's `Backend` contract via thin adapters. There is no separate
`zorm/build.zig`; the host wires it as a module
(`build.zig:158-186`: `b.addModule("zorm", .{ .root_source_file =
b.path("zorm/src/zorm.zig") })`), and zorm's own tests run against that module
directly (`build.zig:336-347`), confirming it builds in isolation.

## Declare an entity

An entity is a plain struct with `pub const zorm_table: []const u8` and fields
built from zorm field types (`zorm/src/reflect.zig:7-12`,
`zorm/src/fields.zig:8-17`):

```zig
const Role = enum { member, admin };

const Account = struct {
    pub const zorm_table = "atp_accounts";
    id: zorm.Pk(64) = .{},          // text primary key
    handle: zorm.Text(253) = .{},
    email: ?zorm.Text(320) = null,  // nullable column
    role: Role = .member,           // enum -> TEXT (by name)
    confirmed: bool = false,        // INTEGER
    created_at: zorm.Timestamp = .{},
    score: f64 = 0,                 // REAL
};
```

The PK is detected from the field types; the table name is `zorm_table`.

## Field types

Exported from `zorm.zig:53-63`; defined in `zorm/src/fields.zig` and mapped by
`zorm/src/reflect.zig:23-43`:

| zorm type        | Zig usage              | Stored as | Notes |
|------------------|------------------------|-----------|-------|
| `Text(N)`        | `Text(64) = .{}`       | TEXT      | Fixed-capacity, N ≤ 1024. |
| `Bytes(N)`       | `Bytes(4096) = .{}`    | BLOB      | Fixed-capacity. |
| `Pk(N)`          | `Pk(64) = .{}`         | TEXT PK   | Caller-supplied text primary key. |
| `AutoPk`         | `AutoPk = .{}`         | INTEGER PK| Auto-increment. |
| `PkInt`          | `PkInt = .{}`          | INTEGER   | Caller-supplied int PK; composite-key member. |
| `Timestamp`      | `Timestamp = .{}`      | INTEGER   | Unix epoch. |
| `Decimal`        | `Decimal = .{}`        | TEXT      | Fixed-point money, lossless. |
| `Uuid`           | `Uuid = .{}`           | TEXT      | 16-byte UUID stored as 36-char canonical string. |
| `Json(N)`        | `Json(N) = .{}`        | TEXT      | Bounded JSON document. |
| `Date`           | `Date = .{}`           | TEXT      | ISO-8601 `YYYY-MM-DD`. |
| `DateTime`       | `DateTime = .{}`       | TEXT      | ISO-8601 `YYYY-MM-DDTHH:MM:SS[.fff]`. |

Native types are used directly: `i64` / `u32` / `bool` → INTEGER, `f64` → REAL,
Zig enums → TEXT (by name), `?T` → nullable column (`fields.zig:1-6`).

### Composite primary keys

Declare two or more caller-supplied PK members in order (`reflect.zig:339-345`):

```zig
const TenantDoc = struct {
    pub const zorm_table = "tenant_docs";
    tenant: zorm.Pk(32) = .{},   // PK part 1
    seq: zorm.PkInt = .{},       // PK part 2
    title: zorm.Text(64) = .{},
};
```

A composite key must be all caller-supplied columns — mixing an `AutoPk` with
other PK columns is a comptime error (`reflect.zig:206`).

## Schema: createTable + Migrator

`createTable(T, dialect)` returns the `CREATE TABLE` DDL string
(`zorm/src/ddl.zig:138`). Related: `dropTable`, `createIndex`, `dropIndex`,
`addColumn`, `dropColumn`, `foreignKeyIndexes` (`zorm.zig:68-75`); FK clauses are
derived from declared relations (`reflect.foreignKeys`).

For managed migrations use `Migrator` (`zorm/src/migrate.zig`):

```zig
const migs = [_]zorm.Migration{
    zorm.initialMigration(User, 2000, .sqlite),
    zorm.initialMigration(Post, 2001, .sqlite),
};
try zorm.Migrator.run(backend, &migs, std.time.timestamp());
```

- `initialMigration(T, id, dialect)` builds `CREATE TABLE` (+ one index per FK
  column); `down` drops the table (`migrate.zig:48-57`).
- `diffMigration(OldT, NewT, id, name, dialect)` is a comptime struct-vs-struct
  diff that emits `addColumn`/`dropColumn`; type changes and renames are out of
  scope (author those explicitly) (`migrate.zig:70-95`).
- `Migrator.run` applies each not-yet-applied migration in ascending `id`, each
  in its own transaction, recording each on success — **idempotent by id**
  (`migrate.zig:161-164`). `Migrator.rollback(...)` reverses down to an id
  (`migrate.zig:228`).
- A `Migration` is `{ id: u32, name, up: []const []const u8, down: ?[]const
  []const u8 }`; ids should be globally unique and strictly increasing,
  namespaced per subsystem (`migrate.zig:36-44`).

## Session / Repository / Query

### Session (identity map + unit of work)

`Session(T, capacity).init(backend)` (`zorm/src/session.zig:36`, `:52`). Key
methods:

- `add(value) -> *T` — stage an insert (`session.zig:115`).
- `get(pk) -> ?*T` — load by PK through the identity map (`session.zig:89`).
- `upsert(*T)` — insert-or-update on the PK; no duplicate row
  (`session.zig:129`). Example (`session.zig:397-409`): upsert the same PK twice
  → second call updates in place.
- `remove(*T)` — stage a delete (`session.zig:134`).
- `flush()` — apply staged inserts/updates/deletes (`session.zig:173`).
- `reset()` — clear the session (`session.zig:57`).

### Repository (CRUD over a backend)

`Repository(T).init(backend)` (`zorm/src/repository.zig:24`, `:31`):

- `find(pk) -> ?*T`, `add(value) -> *T`, `delete(*T)`, `flush()`,
  `isDirty(*const T)` (`repository.zig:39-63`).
- Immediate (non-unit-of-work) variants: `findByPk`, `insertNow`, `updateNow`,
  `deleteByPk` (`repository.zig:71-86`).

Free CRUD functions are also exported: `zorm.insert`, `zorm.upsert`,
`zorm.findByPk`, `zorm.update`, `zorm.delete`, `zorm.deleteByPk`
(`zorm.zig:85-90`). `upsert` emits dialect-correct upsert SQL
(`zorm/src/crud.zig:76`).

### Query (typed SELECT builder)

`Query(T).init(dialect)` (`zorm/src/query.zig:61`, `:81`). Predicates bind as
parameters (never interpolated → injection-safe, `query.zig:4`). Operators
(`Op` enum, `query.zig:29-44`): `eq`, `ne`, `lt`, `lte`, `gt`, `gte`.

Builder methods (`query.zig:156-345`, chainable, return `*Self`):

| Method | Purpose |
|--------|---------|
| `where(field, value)`            | equality predicate |
| `whereOp(field, op, value)`      | predicate with an `Op` |
| `whereLike(field, pattern)`      | `LIKE` |
| `whereIn(field, values)`         | `IN (...)` |
| `whereNull` / `whereNotNull`     | NULL checks |
| `whereBetween(field, lo, hi)`    | range |
| `orWhere(field, op, value)`      | OR-join the next predicate |
| `beginGroup` / `orGroup` / `endGroup` | parenthesised groups |
| `whereText/Int/Bool/Enum`        | typed convenience wrappers |
| `orderBy(field, dir)`            | `Dir` is `.asc` / `.desc` (`query.zig:26`) |
| `offset(n)` / `limit(n)`         | pagination |

Terminal methods: `all(backend, out) -> usize`, `first(backend, *out) -> bool`,
`count(backend) -> i64`, and `allManaged(session, out)` to fill managed
entities (`query.zig:422-476`).

## Dialects

The four SQL dialects (`zorm.Dialect`, defined in
`zorm/src/contract.zig:43-55`):

| Dialect    | Placeholder style |
|------------|-------------------|
| `sqlite`   | `?`               |
| `postgres` | `$1`, `$2`, …     |
| `mysql`    | `?`               |
| `mssql`    | `@p1`, `@p2`, …   |

The dialect is chosen when you create a `Backend` / `Session` / `Query`; the
same entity declaration generates correct SQL for any of the four.
