//! R1 — downstream relay subscription.
//!
//! Where `firehose_consumer.zig` consumes this node's *own* AT firehose
//! (the LOCAL sink → AP outbox path), this module makes the node act as
//! a relay *consumer*: it connects to an EXTERNAL relay's
//! `com.atproto.sync.subscribeRepos` WebSocket, reads framed `#commit`
//! events, and routes each one into the SAME translate→ingest path the
//! local consumer uses (`plugin.handleFirehoseEvent`).
//!
//! ## Wire shape
//!
//! `subscribeRepos` ships each event as a single binary WebSocket frame
//! carrying two concatenated dag-cbor objects (the AT Protocol event
//! stream format):
//!
//!   * header: `{ op: 1, t: "#commit" }`
//!   * body:   `{ seq, repo, time, ops: [ { action, path, record } ] }`
//!
//! Real upstream relays carry the record bytes inside a CAR keyed by CID
//! under `blocks`; we model the structural minimum a consumer needs by
//! inlining each op's record bytes directly under `record` (the same
//! design trade-off `sync_firehose.zig` makes for its `blocks`
//! byte-string). `encodeCommitFrame` is the matching encoder — it is a
//! faithful model of what an external relay emits, used by the tests and
//! reusable by any internal producer. `feed()` is the decode + ingest
//! core; it never opens a socket, so it is exercised directly by tests
//! with no live connection.
//!
//! ## Connection + reconnect
//!
//! `runConnection` drives a `core.ws.stream.Stream` (the existing
//! networking abstraction — `PlainStream` over a TCP fd, or `TlsStream`
//! for `wss://`): it performs the RFC 6455 client handshake, then loops
//! reading bytes and handing complete frames to `feed`. On disconnect
//! the worker loop reconnects, resuming from the persisted cursor
//! (`relay_subscriptions.cursor`, the last consumed `seq`) appended as
//! `?cursor=N` so the upstream replays only what we missed. Buffers are
//! bounded; a frame larger than the read buffer is skipped rather than
//! growing unboundedly.

const std = @import("std");
const core = @import("core");
const c = @import("sqlite").c;
const atproto = @import("protocol_atproto");
const activitypub = @import("protocol_activitypub");
const dag = atproto.dag_cbor;
const ws_frame = core.ws.frame;
const ws_stream = core.ws.stream;
const Arena = core.arena.Arena;

const plugin = @import("plugin.zig");
const subscription = @import("subscription.zig");
const translate = @import("translate.zig");
const identity_map = @import("identity_map.zig");

/// Stream sub-protocol path. Identical to what the LOCAL server exposes;
/// an external relay we subscribe to serves the same XRPC method.
pub const subscribe_path = "/xrpc/com.atproto.sync.subscribeRepos";

/// Read buffer size for the connection loop. One firehose frame
/// (header + a handful of small records) is comfortably under this.
pub const read_buffer_bytes: usize = 64 * 1024;

/// Per-frame arena for translation work. Sized like the local
/// consumer's (`firehose_consumer.processItem`).
const frame_arena_bytes: usize = 64 * 1024;

/// Configuration for the downstream subscriber. Mirrors how the relay's
/// other knobs (`RELAY_BRIDGE_AP_TARGET`, `RELAY_OUTBOX_BACKPRESSURE_CAP`)
/// are read: an env flag enables it, an env URL supplies the target.
pub const Config = struct {
    /// `wss://…` or `ws://…` URL of the external relay's host. The
    /// `subscribe_path` is appended by the connection layer.
    url: []const u8 = "",
    /// Master enable flag. When false the subscriber never connects.
    enable: bool = false,
    /// Local AP host used to synthesize actor IRIs for incoming DIDs.
    relay_host: []const u8 = "speedy-socials.local",

    /// Read `RELAY_DOWNSTREAM_*` env into a Config. `enable` is true only
    /// when `RELAY_DOWNSTREAM_ENABLE` is one of 1/true/yes AND a non-empty
    /// URL is present.
    pub fn fromEnv() Config {
        var cfg: Config = .{};
        if (std.c.getenv("RELAY_DOWNSTREAM_RELAY_URL")) |u| {
            cfg.url = std.mem.sliceTo(u, 0);
        }
        if (std.c.getenv("RELAY_DOWNSTREAM_ENABLE")) |e| {
            const s = std.mem.sliceTo(e, 0);
            cfg.enable = std.mem.eql(u8, s, "1") or
                std.mem.eql(u8, s, "true") or
                std.mem.eql(u8, s, "yes");
        }
        if (std.c.getenv("RELAY_DOWNSTREAM_RELAY_HOST")) |h| {
            const s = std.mem.sliceTo(h, 0);
            if (s.len > 0) cfg.relay_host = s;
        }
        // No URL means nothing to connect to.
        if (cfg.url.len == 0) cfg.enable = false;
        return cfg;
    }
};

/// Observable counters for the admin status route + tests.
pub const Stats = struct {
    frames_seen: std.atomic.Value(u64) = .init(0),
    commits_ingested: std.atomic.Value(u64) = .init(0),
    records_ingested: std.atomic.Value(u64) = .init(0),
    decode_errors: std.atomic.Value(u64) = .init(0),
    reconnects: std.atomic.Value(u64) = .init(0),
    last_seq: std.atomic.Value(i64) = .init(0),
};

/// The result of decoding the header object of a frame.
const Header = struct {
    op: i64 = 0,
    t_buf: [32]u8 = undefined,
    t_len: usize = 0,

    fn t(self: *const Header) []const u8 {
        return self.t_buf[0..self.t_len];
    }
};

pub const Subscriber = struct {
    /// Subscriber's OWN sqlite handle (one per long-lived thread — same
    /// NOMUTEX constraint the firehose consumer documents). Used to
    /// translate + log + persist the cursor.
    db: *c.sqlite3,
    clock: core.clock.Clock,
    cfg: Config,
    /// Io handle used by the live worker to resolve + connect TCP
    /// sockets. The boot layer (`main.zig`) passes its threaded Io here.
    /// `null` is fine for the decode/ingest path (tests) which never
    /// opens a socket; only the live worker requires it.
    io: ?std.Io = null,
    stats: Stats = .{},

    /// Row id of the `relay_subscriptions` row tracking this upstream.
    /// 0 until `ensureSubscription` runs.
    sub_id: i64 = 0,

    /// Last consumed seq. Mirrored to the subscription row's cursor.
    cursor_seq: i64 = 0,

    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = .init(false),

    /// Ensure a `relay_subscriptions` row exists for the configured URL
    /// and load any persisted cursor into `cursor_seq`. Idempotent.
    pub fn ensureSubscription(self: *Subscriber) !void {
        const id = try subscription.subscribe(self.db, self.clock, .atproto_firehose, self.cfg.url);
        self.sub_id = id;
        var buf: [subscription.max_cursor_bytes]u8 = undefined;
        const cur = subscription.getCursor(self.db, id, &buf) catch "";
        if (cur.len > 0) {
            self.cursor_seq = std.fmt.parseInt(i64, cur, 10) catch 0;
            self.stats.last_seq.store(self.cursor_seq, .monotonic);
        }
    }

    /// Persist the current cursor seq to the subscription row.
    fn persistCursor(self: *Subscriber) void {
        if (self.sub_id == 0) return;
        var buf: [24]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, "{d}", .{self.cursor_seq}) catch return;
        subscription.setCursor(self.db, self.sub_id, s) catch {};
    }

    /// R1 ingest core. `frame_bytes` is one complete binary WebSocket
    /// frame (server→client, unmasked) as received from the upstream.
    /// Decodes the WS frame, then the dag-cbor header + body, and routes
    /// each `#commit` op into `plugin.handleFirehoseEvent`. Returns the
    /// number of records ingested from this frame (0 for non-commit
    /// frames or empty commits).
    ///
    /// `frame_bytes` MUST be mutable: WS payload may be masked and
    /// `unmask()` decrypts in place. Upstream servers never mask, so in
    /// practice the bytes are untouched, but the API takes `[]u8` so a
    /// test (or a misbehaving peer that masks) decodes correctly.
    pub fn feed(self: *Subscriber, frame_bytes: []u8) !u32 {
        const res = ws_frame.decode(frame_bytes, false) catch {
            _ = self.stats.decode_errors.fetchAdd(1, .monotonic);
            return error.BadFrame;
        };
        const ok = switch (res) {
            .need_more => return error.NeedMore,
            .ok => |o| o,
        };
        var f = ok.frame;
        f.unmask();
        if (f.opcode != .binary) return 0; // control / text frames: nothing to ingest
        _ = self.stats.frames_seen.fetchAdd(1, .monotonic);
        return self.ingestEventBytes(f.payload);
    }

    /// Decode the dag-cbor header + body that make up one event stream
    /// message and ingest its commit ops. Split out so tests can drive
    /// the CBOR layer directly without a WS frame wrapper.
    pub fn ingestEventBytes(self: *Subscriber, bytes: []const u8) !u32 {
        var dec = dag.Decoder.init(bytes);
        const hdr = decodeHeader(&dec) catch {
            _ = self.stats.decode_errors.fetchAdd(1, .monotonic);
            return error.BadCbor;
        };
        // We only translate commits today. Other kinds (#identity,
        // #account, …) advance the cursor but produce no AP activity.
        if (!std.mem.eql(u8, hdr.t(), "#commit")) {
            return self.skipNonCommit(&dec);
        }
        return self.ingestCommit(&dec);
    }

    /// Walk a `#commit` body and ingest each op. The decoder is
    /// positioned just past the header.
    fn ingestCommit(self: *Subscriber, dec: *dag.Decoder) !u32 {
        const body_head = dec.nextEvent() catch return error.BadCbor;
        const pairs = switch (body_head) {
            .map_start => |n| n,
            else => return error.BadCbor,
        };

        var seq: i64 = 0;
        var did_buf: [256]u8 = undefined;
        var did_len: usize = 0;
        // Op storage: bounded — one commit rarely carries many records.
        var ops: [16]OpView = undefined;
        var n_ops: usize = 0;

        var i: u64 = 0;
        while (i < pairs) : (i += 1) {
            const k_ev = dec.nextEvent() catch return error.BadCbor;
            const key = switch (k_ev) {
                .text => |s| s,
                else => return error.BadCbor,
            };
            if (std.mem.eql(u8, key, "seq")) {
                const v = dec.nextEvent() catch return error.BadCbor;
                seq = switch (v) {
                    .uint => |u| @intCast(u),
                    .int => |x| x,
                    else => 0,
                };
            } else if (std.mem.eql(u8, key, "repo")) {
                const v = dec.nextEvent() catch return error.BadCbor;
                switch (v) {
                    .text => |s| {
                        const cap = @min(s.len, did_buf.len);
                        @memcpy(did_buf[0..cap], s[0..cap]);
                        did_len = cap;
                    },
                    else => return error.BadCbor,
                }
            } else if (std.mem.eql(u8, key, "ops")) {
                n_ops = try decodeOps(dec, &ops);
            } else {
                // Unknown key — skip its value (text/uint/etc.). Records
                // and ops are the only nested values we model; anything
                // else here is a scalar.
                skipValue(dec) catch return error.BadCbor;
            }
        }

        if (did_len == 0) return error.BadCbor;
        const did = did_buf[0..did_len];

        var ingested: u32 = 0;
        var arena_buf: [frame_arena_bytes]u8 = undefined;
        for (ops[0..n_ops]) |op| {
            const action = op.action();
            const is_delete = std.mem.eql(u8, action, "delete");
            const is_create_update = std.mem.eql(u8, action, "create") or std.mem.eql(u8, action, "update");
            if (!is_delete and !is_create_update) continue;
            // A create/update with no record body carries nothing to
            // translate; a delete legitimately has none.
            if (is_create_update and op.record_len == 0) continue;

            // path = "<collection>/<rkey>"; collection is everything up
            // to the last '/'.
            const path = op.path();
            const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse continue;
            const collection = path[0..slash];

            // at_uri = "at://<did>/<path>"
            var uri_buf: [512]u8 = undefined;
            const at_uri = std.fmt.bufPrint(&uri_buf, "at://{s}/{s}", .{ did, path }) catch continue;

            if (is_delete) {
                // A record deletion on the upstream firehose → an AP
                // Delete (post) or Undo{Like/Announce/Block} for the
                // bridged interaction. Only bridged collections produce
                // an activity; others are logged as seen.
                if (translate.AtKind.fromCollection(collection) == null) {
                    var reason_buf: [128]u8 = undefined;
                    const reason = std.fmt.bufPrint(&reason_buf, "unsupported collection (delete): {s}", .{collection}) catch "unsupported collection";
                    _ = subscription.appendLog(self.db, self.clock, .at_to_ap, at_uri, "", true, reason) catch {};
                    continue;
                }
                // Dedup the delete on a distinct key so it doesn't clash
                // with the create's at_uri log row.
                var dkey_buf: [560]u8 = undefined;
                const dkey = std.fmt.bufPrint(&dkey_buf, "{s} [deleted]", .{at_uri}) catch at_uri;
                if (subscription.hasSuccessfulLog(self.db, .at_to_ap, dkey)) continue;
                self.ingestUpstreamDelete(did, collection, at_uri, dkey) catch |err| {
                    std.log.warn("relay downstream: delete ingest failed: {s}", .{@errorName(err)});
                    continue;
                };
                ingested += 1;
                _ = self.stats.records_ingested.fetchAdd(1, .monotonic);
                core.metrics.incRelayAtToAp();
                continue;
            }

            // Dedup: a reconnect replays from the cursor and may resend
            // an event we already ingested. The translation log keys on
            // at_uri so skip without re-enqueuing.
            if (subscription.hasSuccessfulLog(self.db, .at_to_ap, at_uri)) continue;

            var arena = Arena.init(&arena_buf);
            const ev: plugin.FirehoseEvent = .{
                .at_uri = at_uri,
                .did = did,
                .collection = collection,
                .record_json = op.record(),
                .fallback_created_at = "",
            };
            _ = plugin.handleFirehoseEvent(
                self.db,
                self.clock,
                self.cfg.relay_host,
                ev,
                &arena,
            ) catch |err| switch (err) {
                error.UnsupportedKind => {
                    // Log so the admin route shows we saw it, mirroring
                    // the local consumer's A6 behaviour.
                    var reason_buf: [128]u8 = undefined;
                    const reason = std.fmt.bufPrint(&reason_buf, "unsupported collection: {s}", .{collection}) catch "unsupported collection";
                    _ = subscription.appendLog(self.db, self.clock, .at_to_ap, at_uri, "", true, reason) catch {};
                    continue;
                },
                else => return err,
            };
            ingested += 1;
            _ = self.stats.records_ingested.fetchAdd(1, .monotonic);
            core.metrics.incRelayAtToAp();
        }

        // Advance + persist the cursor regardless of how many records
        // translated — a delete-only or unsupported commit still moves
        // the firehose position forward.
        if (seq > self.cursor_seq) {
            self.cursor_seq = seq;
            self.stats.last_seq.store(seq, .monotonic);
            self.persistCursor();
        }
        _ = self.stats.commits_ingested.fetchAdd(1, .monotonic);
        return ingested;
    }

    /// Translate an upstream record DELETION into an AP activity and log
    /// it. A post deletion → `Delete`; a like/repost/block deletion →
    /// `Undo{Like/Announce/Block}` (unlike / unrepost / unblock). The
    /// synthetic AP actor for the upstream DID is minted on demand so the
    /// activity carries the same actor IRI the create-side used. The
    /// activity id reproduces the bridged create's activity id (derived
    /// from the same at_uri) so a receiving peer matches + undoes it.
    fn ingestUpstreamDelete(
        self: *Subscriber,
        did: []const u8,
        collection: []const u8,
        at_uri: []const u8,
        dedup_key: []const u8,
    ) !void {
        const kind = translate.AtKind.fromCollection(collection) orelse return error.UnsupportedKind;

        var arena_buf: [frame_arena_bytes]u8 = undefined;
        var arena = Arena.init(&arena_buf);

        // Resolve / mint the synthetic AP actor for this DID (same path
        // the create translator uses).
        var maybe_actor = try identity_map.actorForDid(self.db, did, &arena);
        if (maybe_actor == null) {
            const synth = try identity_map.syntheticActorForDid(self.cfg.relay_host, did, &arena);
            try identity_map.upsert(self.db, self.clock, did, synth);
            maybe_actor = synth;
        }
        const actor = maybe_actor.?;

        // Bridged activity id = "https://<host>/activities/<at_uri with
        // '/'→':'>" — identical to plugin.buildApId's encoding.
        const ap_id = try buildActivityId(self.cfg.relay_host, at_uri, &arena);

        const alloc = arena.allocator();
        const buf = try alloc.alloc(u8, 4 * 1024);
        const payload = switch (kind) {
            .post => try std.fmt.bufPrint(buf,
                \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}#delete","type":"Delete","actor":"{s}","object":"{s}"}}
            , .{ ap_id, actor, ap_id }),
            .like, .repost, .block => blk: {
                const inner: []const u8 = switch (kind) {
                    .like => "Like",
                    .repost => "Announce",
                    .block => "Block",
                    else => unreachable,
                };
                break :blk try std.fmt.bufPrint(buf,
                    \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}#undo","type":"Undo","actor":"{s}","object":{{"id":"{s}","type":"{s}","actor":"{s}"}}}}
                , .{ ap_id, actor, ap_id, inner, actor });
            },
            .follow => try std.fmt.bufPrint(buf,
                \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}#undo","type":"Undo","actor":"{s}","object":{{"id":"{s}","type":"Follow","actor":"{s}"}}}}
            , .{ ap_id, actor, ap_id, actor }),
        };

        // Fan the activity out to the actor's AP followers (parity with
        // the create-side delivery), then log.
        self.deliverToFollowers(actor, payload, &arena);
        _ = subscription.appendLog(self.db, self.clock, .at_to_ap, dedup_key, ap_id, true, "") catch {};
    }

    /// Enqueue `payload` into `ap_federation_outbox` for every follower of
    /// `actor`. Best-effort — delivery failures are non-fatal.
    fn deliverToFollowers(self: *Subscriber, actor: []const u8, payload: []const u8, arena: *Arena) void {
        var followers_buf: [64]@import("followers.zig").Follower = undefined;
        const n = @import("followers.zig").list(self.db, actor, &followers_buf) catch return;
        var key_id_buf: [256 + 9]u8 = undefined;
        if (actor.len + 9 > key_id_buf.len) return;
        @memcpy(key_id_buf[0..actor.len], actor);
        @memcpy(key_id_buf[actor.len..][0..9], "#main-key");
        const key_id = key_id_buf[0 .. actor.len + 9];
        _ = arena;
        for (followers_buf[0..n]) |f| {
            const recipients = [_]activitypub.delivery.Recipient{.{ .inbox = f.inbox() }};
            _ = activitypub.delivery.enqueueDeliveries(self.db, self.clock, &recipients, payload, key_id) catch continue;
            core.metrics.incApOutboxEnqueued();
        }
    }

    /// Advance the cursor for a non-commit event (no AP activity). The
    /// decoder is positioned just past the header.
    fn skipNonCommit(self: *Subscriber, dec: *dag.Decoder) !u32 {
        const body_head = dec.nextEvent() catch return error.BadCbor;
        const pairs = switch (body_head) {
            .map_start => |n| n,
            else => return 0,
        };
        var i: u64 = 0;
        while (i < pairs) : (i += 1) {
            const k_ev = dec.nextEvent() catch return error.BadCbor;
            const key = switch (k_ev) {
                .text => |s| s,
                else => return error.BadCbor,
            };
            if (std.mem.eql(u8, key, "seq")) {
                const v = dec.nextEvent() catch return error.BadCbor;
                const seq: i64 = switch (v) {
                    .uint => |u| @intCast(u),
                    .int => |x| x,
                    else => 0,
                };
                if (seq > self.cursor_seq) {
                    self.cursor_seq = seq;
                    self.stats.last_seq.store(seq, .monotonic);
                    self.persistCursor();
                }
            } else {
                skipValue(dec) catch return error.BadCbor;
            }
        }
        return 0;
    }
};

/// A single decoded commit op viewed against fixed inline storage.
const OpView = struct {
    action_buf: [16]u8 = undefined,
    action_len: usize = 0,
    path_buf: [256]u8 = undefined,
    path_len: usize = 0,
    record_buf: [8192]u8 = undefined,
    record_len: usize = 0,

    fn action(self: *const OpView) []const u8 {
        return self.action_buf[0..self.action_len];
    }
    fn path(self: *const OpView) []const u8 {
        return self.path_buf[0..self.path_len];
    }
    fn record(self: *const OpView) []const u8 {
        return self.record_buf[0..self.record_len];
    }
};

/// Decode the header object `{ op, t }`. Leaves the decoder positioned
/// at the body object.
fn decodeHeader(dec: *dag.Decoder) !Header {
    var hdr: Header = .{};
    const head = try dec.nextEvent();
    const pairs = switch (head) {
        .map_start => |n| n,
        else => return error.BadCbor,
    };
    var i: u64 = 0;
    while (i < pairs) : (i += 1) {
        const k_ev = try dec.nextEvent();
        const key = switch (k_ev) {
            .text => |s| s,
            else => return error.BadCbor,
        };
        const v_ev = try dec.nextEvent();
        if (std.mem.eql(u8, key, "op")) {
            hdr.op = switch (v_ev) {
                .uint => |u| @intCast(u),
                .int => |x| x,
                else => 0,
            };
        } else if (std.mem.eql(u8, key, "t")) {
            switch (v_ev) {
                .text => |s| {
                    const cap = @min(s.len, hdr.t_buf.len);
                    @memcpy(hdr.t_buf[0..cap], s[0..cap]);
                    hdr.t_len = cap;
                },
                else => {},
            }
        }
    }
    return hdr;
}

/// Decode the `ops` array `[ { action, path, record } ]`. The decoder is
/// positioned at the array header. Returns the number of ops written.
fn decodeOps(dec: *dag.Decoder, out: []OpView) !usize {
    const arr = dec.nextEvent() catch return error.BadCbor;
    const count = switch (arr) {
        .array_start => |n| n,
        else => return error.BadCbor,
    };
    var written: usize = 0;
    var i: u64 = 0;
    while (i < count) : (i += 1) {
        const m = dec.nextEvent() catch return error.BadCbor;
        const pairs = switch (m) {
            .map_start => |n| n,
            else => return error.BadCbor,
        };
        var op: OpView = .{};
        var p: u64 = 0;
        while (p < pairs) : (p += 1) {
            const k_ev = dec.nextEvent() catch return error.BadCbor;
            const key = switch (k_ev) {
                .text => |s| s,
                else => return error.BadCbor,
            };
            const v_ev = dec.nextEvent() catch return error.BadCbor;
            if (std.mem.eql(u8, key, "action")) {
                switch (v_ev) {
                    .text => |s| {
                        const cap = @min(s.len, op.action_buf.len);
                        @memcpy(op.action_buf[0..cap], s[0..cap]);
                        op.action_len = cap;
                    },
                    else => {},
                }
            } else if (std.mem.eql(u8, key, "path")) {
                switch (v_ev) {
                    .text => |s| {
                        const cap = @min(s.len, op.path_buf.len);
                        @memcpy(op.path_buf[0..cap], s[0..cap]);
                        op.path_len = cap;
                    },
                    else => {},
                }
            } else if (std.mem.eql(u8, key, "record")) {
                switch (v_ev) {
                    .bytes => |s| {
                        const cap = @min(s.len, op.record_buf.len);
                        @memcpy(op.record_buf[0..cap], s[0..cap]);
                        op.record_len = cap;
                    },
                    .text => |s| {
                        const cap = @min(s.len, op.record_buf.len);
                        @memcpy(op.record_buf[0..cap], s[0..cap]);
                        op.record_len = cap;
                    },
                    else => {},
                }
            }
            // Unknown keys inside an op carry scalar values already
            // consumed by `v_ev`; nothing to skip.
        }
        if (written < out.len) {
            out[written] = op;
            written += 1;
        }
    }
    return written;
}

/// Consume exactly one CBOR value (scalar or container) from the decoder.
/// Used to skip values bound to keys we don't model. Bounded by the
/// decoder's own item/depth caps.
fn skipValue(dec: *dag.Decoder) !void {
    var pending: u64 = 1;
    var guard: u32 = 0;
    while (pending > 0) {
        guard += 1;
        if (guard > dag.max_decode_items) return error.BadCbor;
        const ev = try dec.nextEvent();
        pending -= 1;
        switch (ev) {
            .array_start => |n| pending += n,
            .map_start => |n| pending += n * 2,
            else => {},
        }
    }
}

/// Build the bridged AP activity id from an AT-URI, matching the
/// encoding `plugin.buildApId(host, "activities", at_uri, …)` uses for
/// create-side activities: `https://<host>/activities/<at_uri with the
/// `at://` prefix stripped and '/'→':'>`. Used by the delete path so the
/// Delete/Undo references the same id the original Create/Like/etc. got.
fn buildActivityId(host: []const u8, at_uri: []const u8, arena: *Arena) ![]const u8 {
    const alloc = arena.allocator();
    const tail = if (std.mem.startsWith(u8, at_uri, "at://")) at_uri[5..] else at_uri;
    const total = "https://".len + host.len + "/activities/".len + tail.len;
    const buf = try alloc.alloc(u8, total);
    var w: usize = 0;
    @memcpy(buf[w..][0.."https://".len], "https://");
    w += "https://".len;
    @memcpy(buf[w..][0..host.len], host);
    w += host.len;
    @memcpy(buf[w..][0.."/activities/".len], "/activities/");
    w += "/activities/".len;
    for (tail) |ch| {
        buf[w] = if (ch == '/') ':' else ch;
        w += 1;
    }
    return buf[0..w];
}

// ── Encoder (faithful model of an external relay's frame) ───────────

/// One op to encode into a `#commit` frame.
pub const EncodeOp = struct {
    action: []const u8,
    /// "<collection>/<rkey>"
    path: []const u8,
    /// Raw record bytes (JSON or CBOR — the consumer treats it as the
    /// record body and hands it to the translator as `record_json`).
    record: []const u8,
};

/// Encode a complete `#commit` event-stream message (header + body) into
/// `out`, returning the written slice. This is exactly the byte sequence
/// an external relay places in the binary WebSocket frame payload.
pub fn encodeCommitMessage(
    out: []u8,
    seq: i64,
    repo_did: []const u8,
    time_secs: i64,
    ops: []const EncodeOp,
) ![]const u8 {
    var enc = dag.Encoder.init(out);
    // Header: { op: 1, t: "#commit" }  (keys length-then-lex: "op"<"t")
    try enc.writeMapHeader(2);
    try enc.writeText("op");
    try enc.writeUInt(1);
    try enc.writeText("t");
    try enc.writeText("#commit");

    // Body: { seq, repo, time, ops }  (canonical order: seq(3) < ops(3,
    // lex "ops">"seq"? "ops"<"seq" lexically) ...). To stay unambiguous
    // for our own decoder we don't rely on canonical order — the decoder
    // reads keys by name. We still emit a stable, readable order.
    try enc.writeMapHeader(4);
    try enc.writeText("seq");
    try enc.writeUInt(@intCast(seq));
    try enc.writeText("repo");
    try enc.writeText(repo_did);
    try enc.writeText("time");
    try enc.writeUInt(@intCast(time_secs));
    try enc.writeText("ops");
    try enc.writeArrayHeader(ops.len);
    for (ops) |op| {
        try enc.writeMapHeader(3);
        try enc.writeText("action");
        try enc.writeText(op.action);
        try enc.writeText("path");
        try enc.writeText(op.path);
        try enc.writeText("record");
        try enc.writeBytesValue(op.record);
    }
    return enc.written();
}

/// Wrap an already-encoded event-stream message in an unmasked binary
/// WebSocket frame (server→client direction). Returns the framed slice.
pub fn frameMessage(message: []const u8, out: []u8) ![]const u8 {
    const n = ws_frame.encode(.binary, message, true, out) catch return error.EncodeFailed;
    return out[0..n];
}

// ── Connection driver ───────────────────────────────────────────────

/// Parsed `ws://host:port` / `wss://host:port` target.
const Target = struct {
    tls: bool,
    host_buf: [core.http_client.max_host_bytes]u8 = undefined,
    host_len: usize = 0,
    port: u16,

    fn host(self: *const Target) []const u8 {
        return self.host_buf[0..self.host_len];
    }
};

fn parseTarget(url: []const u8) !Target {
    var t: Target = .{ .tls = false, .port = 80 };
    var rest = url;
    if (std.mem.startsWith(u8, rest, "wss://")) {
        t.tls = true;
        t.port = 443;
        rest = rest["wss://".len..];
    } else if (std.mem.startsWith(u8, rest, "ws://")) {
        t.tls = false;
        t.port = 80;
        rest = rest["ws://".len..];
    } else {
        return error.UnsupportedScheme;
    }
    // Authority ends at the first '/'.
    const auth_end = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const authority = rest[0..auth_end];
    // Optional ":port".
    var hostpart = authority;
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |ci| {
        hostpart = authority[0..ci];
        t.port = std.fmt.parseInt(u16, authority[ci + 1 ..], 10) catch t.port;
    }
    if (hostpart.len == 0 or hostpart.len > t.host_buf.len) return error.BadHost;
    @memcpy(t.host_buf[0..hostpart.len], hostpart);
    t.host_len = hostpart.len;
    return t;
}

/// Perform the RFC 6455 client opening handshake over `stream`. Sends
/// the upgrade request (with `?cursor=N` when `cursor_seq > 0`), reads
/// the 101 response, and validates `Sec-WebSocket-Accept`. After this
/// returns Ok the stream carries binary firehose frames.
fn clientHandshake(
    stream: ws_stream.Stream,
    target: *const Target,
    cursor_seq: i64,
) !void {
    // Build a 16-byte random nonce, base64-encode it. The Sec-WebSocket-
    // Key nonce is not a security boundary (RFC 6455 §1.3 — it only
    // guards against caching proxies), so an OS-seeded PRNG is fine and
    // avoids the stripped std's missing `std.crypto.random`.
    var rng = core.rng.Rng.initFromOs();
    var nonce: [16]u8 = undefined;
    rng.random().bytes(&nonce);
    var key_b64: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&key_b64, &nonce);

    var req_buf: [1024]u8 = undefined;
    const req = if (cursor_seq > 0)
        try std.fmt.bufPrint(&req_buf,
            "GET {s}?cursor={d} HTTP/1.1\r\n" ++
                "Host: {s}\r\n" ++
                "Upgrade: websocket\r\n" ++
                "Connection: Upgrade\r\n" ++
                "Sec-WebSocket-Key: {s}\r\n" ++
                "Sec-WebSocket-Version: 13\r\n\r\n",
            .{ subscribe_path, cursor_seq, target.host(), key_b64 })
    else
        try std.fmt.bufPrint(&req_buf,
            "GET {s} HTTP/1.1\r\n" ++
                "Host: {s}\r\n" ++
                "Upgrade: websocket\r\n" ++
                "Connection: Upgrade\r\n" ++
                "Sec-WebSocket-Key: {s}\r\n" ++
                "Sec-WebSocket-Version: 13\r\n\r\n",
            .{ subscribe_path, target.host(), key_b64 });

    try stream.writeAll(req);

    // Read the response headers (bounded). We need the full header block
    // terminated by \r\n\r\n.
    var resp: [4096]u8 = undefined;
    var got: usize = 0;
    var spins: u32 = 0;
    while (spins < 2000) : (spins += 1) {
        if (std.mem.indexOf(u8, resp[0..got], "\r\n\r\n") != null) break;
        if (got >= resp.len) return error.HandshakeTooLarge;
        const n = stream.readNonblocking(resp[got..]) catch return error.HandshakeReadFailed;
        if (n == 0) {
            sleepMs(2);
            continue;
        }
        got += n;
    }
    const hdr_end = std.mem.indexOf(u8, resp[0..got], "\r\n\r\n") orelse return error.HandshakeIncomplete;
    const head = resp[0..hdr_end];
    if (std.mem.indexOf(u8, head, " 101 ") == null) return error.HandshakeNot101;

    // Validate Sec-WebSocket-Accept matches our key.
    var expected: [28]u8 = undefined;
    core.ws.handshake.computeAccept(&key_b64, &expected);
    if (findHeaderValue(head, "sec-websocket-accept")) |val| {
        if (!std.mem.eql(u8, std.mem.trim(u8, val, " "), &expected)) return error.HandshakeBadAccept;
    } else {
        return error.HandshakeNoAccept;
    }
}

/// Case-insensitive header lookup over a raw header block.
fn findHeaderValue(block: []const u8, name_lower: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, block, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const k = line[0..colon];
        if (k.len != name_lower.len) continue;
        var match = true;
        for (k, name_lower) |kc, nc| {
            if (std.ascii.toLower(kc) != nc) {
                match = false;
                break;
            }
        }
        if (match) return line[colon + 1 ..];
    }
    return null;
}

/// Drive one connection lifetime: handshake, then read+feed frames until
/// the socket closes, errors, or `stop_flag` is set. The frame reader
/// accumulates bytes in a bounded buffer and feeds each complete frame.
/// Returns when the connection ends; the caller decides whether to
/// reconnect.
pub fn runConnection(self: *Subscriber, stream: ws_stream.Stream) !void {
    const target = try parseTarget(self.cfg.url);
    try clientHandshake(stream, &target, self.cursor_seq);

    var buf: [read_buffer_bytes]u8 = undefined;
    var filled: usize = 0;

    while (!self.stop_flag.load(.acquire)) {
        // Drain any complete frames already buffered.
        while (filled >= 2) {
            const res = ws_frame.decode(buf[0..filled], false) catch {
                // Unrecoverable frame error — drop the buffer and let the
                // outer loop continue reading (a real peer would close).
                filled = 0;
                _ = self.stats.decode_errors.fetchAdd(1, .monotonic);
                break;
            };
            switch (res) {
                .need_more => break,
                .ok => |ok| {
                    var f = ok.frame;
                    f.unmask();
                    switch (f.opcode) {
                        .binary => {
                            _ = self.stats.frames_seen.fetchAdd(1, .monotonic);
                            _ = self.ingestEventBytes(f.payload) catch {};
                        },
                        .close => return,
                        .ping => {}, // server→client pings are rare; ignore
                        else => {},
                    }
                    // Shift consumed bytes out.
                    const consumed = ok.consumed;
                    std.mem.copyForwards(u8, buf[0 .. filled - consumed], buf[consumed..filled]);
                    filled -= consumed;
                },
            }
        }

        if (filled == buf.len) {
            // A single frame larger than the buffer — skip it to avoid a
            // wedged connection. Bounded-buffer policy.
            filled = 0;
            _ = self.stats.decode_errors.fetchAdd(1, .monotonic);
        }

        const n = stream.readNonblocking(buf[filled..]) catch return error.ConnectionRead;
        if (n == 0) {
            sleepMs(20);
            continue;
        }
        filled += n;
    }
}

fn sleepMs(ms: u32) void {
    var req: std.c.timespec = .{
        .sec = 0,
        .nsec = @intCast(@as(i64, ms) * std.time.ns_per_ms),
    };
    _ = std.c.nanosleep(&req, &req);
}

// ── Live connection worker (TCP via PlainStream) ────────────────────

/// Background worker: maintain a connection to the upstream relay,
/// reconnecting with exponential-ish backoff and cursor resume. Each
/// iteration resolves + connects a TCP socket, wraps it in a
/// `PlainStream`, and drives `runConnection`. TLS (`wss://`) requires a
/// TLS adapter the boot layer wires; until then a `wss://` target uses
/// the plain TCP path only when the boot environment provides a
/// terminating proxy. The worker never blocks the relay's other threads.
fn workerLoop(self: *Subscriber) void {
    var backoff_ms: u32 = 250;
    const backoff_max_ms: u32 = 15_000;

    while (!self.stop_flag.load(.acquire)) {
        connectOnce(self) catch |err| {
            std.log.warn("relay downstream: connection ended: {s}", .{@errorName(err)});
        };
        if (self.stop_flag.load(.acquire)) break;
        _ = self.stats.reconnects.fetchAdd(1, .monotonic);
        // Backoff before reconnecting; reload the cursor so we resume.
        var waited: u32 = 0;
        while (waited < backoff_ms and !self.stop_flag.load(.acquire)) : (waited += 50) {
            sleepMs(50);
        }
        backoff_ms = @min(backoff_ms * 2, backoff_max_ms);
        reloadCursor(self);
    }
}

fn reloadCursor(self: *Subscriber) void {
    if (self.sub_id == 0) return;
    var buf: [subscription.max_cursor_bytes]u8 = undefined;
    const cur = subscription.getCursor(self.db, self.sub_id, &buf) catch return;
    if (cur.len > 0) {
        self.cursor_seq = std.fmt.parseInt(i64, cur, 10) catch self.cursor_seq;
    }
}

fn connectOnce(self: *Subscriber) !void {
    const target = try parseTarget(self.cfg.url);
    if (target.tls) {
        // TLS termination for `wss://` needs a TLS adapter wired by the
        // boot layer (the same `core.tls` backend the HTTP client uses).
        // Until that is threaded through, refuse rather than silently
        // talking plaintext to a TLS port.
        return error.TlsNotWired;
    }

    const io = self.io orelse return error.NoIoHandle;
    var addr = std.Io.net.IpAddress.resolve(io, target.host(), target.port) catch return error.DnsFailed;
    var net_stream = std.Io.net.IpAddress.connect(&addr, io, .{ .mode = .stream }) catch return error.ConnectFailed;
    const fd = net_stream.socket.handle;
    defer net_stream.close(io);

    var plain = ws_stream.PlainStream.init(fd);
    try runConnection(self, plain.stream());
}

/// Start the subscriber's background worker. Idempotent-ish: caller must
/// not call twice on the same struct. Returns immediately; the worker
/// runs until `stop` is called. No-op (returns without spawning) when
/// the config is disabled.
pub fn start(self: *Subscriber) !void {
    if (!self.cfg.enable) return;
    try self.ensureSubscription();
    self.stop_flag.store(false, .release);
    self.thread = try std.Thread.spawn(.{}, workerLoop, .{self});
}

/// Stop the worker and join it.
pub fn stop(self: *Subscriber) void {
    self.stop_flag.store(true, .release);
    if (self.thread) |t| {
        t.join();
        self.thread = null;
    }
}

// ── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;
const schema_mod = @import("schema.zig");
const at_schema = atproto.schema;

fn setupDb() !*c.sqlite3 {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    for (at_schema.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
    }
    for (activitypub.schema.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
    }
    for (schema_mod.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
    }
    return db;
}

test "R1: parseTarget splits scheme/host/port" {
    const t1 = try parseTarget("wss://relay.example.com/foo");
    try testing.expect(t1.tls);
    try testing.expectEqual(@as(u16, 443), t1.port);
    try testing.expectEqualStrings("relay.example.com", t1.host());

    const t2 = try parseTarget("ws://127.0.0.1:9999");
    try testing.expect(!t2.tls);
    try testing.expectEqual(@as(u16, 9999), t2.port);
    try testing.expectEqualStrings("127.0.0.1", t2.host());

    try testing.expectError(error.UnsupportedScheme, parseTarget("http://x"));
}

test "R1: Config.fromEnv disables without a URL" {
    // No env set in the test process → disabled.
    const cfg = Config.fromEnv();
    try testing.expect(!cfg.enable);
}

test "R1: end-to-end — synthetic #commit frame decoded + translated + ingested" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var sc = core.clock.SimClock.init(1_715_000_000);
    var sub: Subscriber = .{
        .db = db,
        .clock = sc.clock(),
        .cfg = .{ .url = "ws://upstream.test:8080", .enable = true, .relay_host = "relay.test" },
    };
    try sub.ensureSubscription();

    // Build a synthetic #commit frame exactly as an external relay would,
    // using the atproto firehose dag-cbor encoder.
    const did = "did:plc:upstream_alice";
    const record_json = "{\"$type\":\"app.bsky.feed.post\",\"text\":\"from upstream relay\",\"createdAt\":\"2026-05-16T00:00:00Z\"}";
    const ops = [_]EncodeOp{.{
        .action = "create",
        .path = "app.bsky.feed.post/rkey123",
        .record = record_json,
    }};
    var msg_buf: [4096]u8 = undefined;
    const msg = try encodeCommitMessage(&msg_buf, 4242, did, 1_715_000_000, &ops);

    var frame_buf: [4096]u8 = undefined;
    const framed = try frameMessage(msg, &frame_buf);
    // `feed` requires a mutable slice (it may unmask in place).
    var frame_mut: [4096]u8 = undefined;
    @memcpy(frame_mut[0..framed.len], framed);

    const ingested = try sub.feed(frame_mut[0..framed.len]);
    try testing.expectEqual(@as(u32, 1), ingested);
    try testing.expectEqual(@as(u64, 1), sub.stats.records_ingested.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), sub.stats.commits_ingested.load(.monotonic));

    // Cursor advanced + persisted.
    try testing.expectEqual(@as(i64, 4242), sub.cursor_seq);
    var cbuf: [32]u8 = undefined;
    try testing.expectEqualStrings("4242", try subscription.getCursor(db, sub.sub_id, &cbuf));

    // Translation log got an at_to_ap entry keyed on the built at_uri.
    const expected_uri = "at://did:plc:upstream_alice/app.bsky.feed.post/rkey123";
    var log_rows: [4]subscription.LogEntry = undefined;
    const n = try subscription.listLog(db, 0, &log_rows);
    try testing.expect(n >= 1);
    try testing.expectEqual(subscription.Direction.at_to_ap, log_rows[0].direction);
    try testing.expectEqualStrings(expected_uri, log_rows[0].sourceId());
    try testing.expect(log_rows[0].success);

    // Identity map row minted for the upstream DID.
    var abuf: [4096]u8 = undefined;
    var arena = Arena.init(&abuf);
    const actor = try plugin.identity_map.actorForDid(db, did, &arena);
    try testing.expect(actor != null);
}

test "R1: replayed commit is deduped (no duplicate log row)" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var sc = core.clock.SimClock.init(1_716_000_000);
    var sub: Subscriber = .{
        .db = db,
        .clock = sc.clock(),
        .cfg = .{ .url = "ws://upstream.test", .enable = true, .relay_host = "relay.test" },
    };
    try sub.ensureSubscription();

    const did = "did:plc:dedup_bob";
    const record_json = "{\"$type\":\"app.bsky.feed.post\",\"text\":\"dup\",\"createdAt\":\"2026-05-19T00:00:00Z\"}";
    const ops = [_]EncodeOp{.{ .action = "create", .path = "app.bsky.feed.post/p1", .record = record_json }};
    var msg_buf: [4096]u8 = undefined;
    const msg = try encodeCommitMessage(&msg_buf, 100, did, 1_716_000_000, &ops);

    // Feed the same message twice (simulating a reconnect replay).
    const first = try sub.ingestEventBytes(msg);
    try testing.expectEqual(@as(u32, 1), first);
    const second = try sub.ingestEventBytes(msg);
    try testing.expectEqual(@as(u32, 0), second); // deduped

    var log_rows: [8]subscription.LogEntry = undefined;
    const n = try subscription.listLog(db, 0, &log_rows);
    // Exactly one successful at_to_ap row for this uri.
    var count: u32 = 0;
    for (log_rows[0..n]) |r| {
        if (std.mem.eql(u8, r.sourceId(), "at://did:plc:dedup_bob/app.bsky.feed.post/p1")) count += 1;
    }
    try testing.expectEqual(@as(u32, 1), count);
}

test "R1: unsupported collection logged, cursor still advances" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var sc = core.clock.SimClock.init(1);
    var sub: Subscriber = .{
        .db = db,
        .clock = sc.clock(),
        .cfg = .{ .url = "ws://upstream.test", .enable = true, .relay_host = "relay.test" },
    };
    try sub.ensureSubscription();

    const ops = [_]EncodeOp{.{ .action = "create", .path = "app.bsky.feed.threadgate/x", .record = "{}" }};
    var msg_buf: [1024]u8 = undefined;
    const msg = try encodeCommitMessage(&msg_buf, 77, "did:plc:tg", 1, &ops);

    const ingested = try sub.ingestEventBytes(msg);
    try testing.expectEqual(@as(u32, 0), ingested); // unsupported → not counted
    try testing.expectEqual(@as(i64, 77), sub.cursor_seq); // cursor advanced

    var log_rows: [4]subscription.LogEntry = undefined;
    const n = try subscription.listLog(db, 0, &log_rows);
    try testing.expect(n >= 1);
    try testing.expect(std.mem.startsWith(u8, log_rows[0].errorMsg(), "unsupported collection"));
}

test "R1: non-commit frame advances cursor without ingesting" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var sc = core.clock.SimClock.init(1);
    var sub: Subscriber = .{
        .db = db,
        .clock = sc.clock(),
        .cfg = .{ .url = "ws://upstream.test", .enable = true, .relay_host = "relay.test" },
    };
    try sub.ensureSubscription();

    // Encode an #identity-style message: header {op,t:"#identity"} + body {seq,did}.
    var buf: [256]u8 = undefined;
    var enc = dag.Encoder.init(&buf);
    try enc.writeMapHeader(2);
    try enc.writeText("op");
    try enc.writeUInt(1);
    try enc.writeText("t");
    try enc.writeText("#identity");
    try enc.writeMapHeader(2);
    try enc.writeText("seq");
    try enc.writeUInt(555);
    try enc.writeText("did");
    try enc.writeText("did:plc:ident");
    const msg = enc.written();

    const ingested = try sub.ingestEventBytes(msg);
    try testing.expectEqual(@as(u32, 0), ingested);
    try testing.expectEqual(@as(i64, 555), sub.cursor_seq);
}

test "R1: multi-op commit ingests each create/update AND each bridged delete" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var sc = core.clock.SimClock.init(1_717_000_000);
    var sub: Subscriber = .{
        .db = db,
        .clock = sc.clock(),
        .cfg = .{ .url = "ws://upstream.test", .enable = true, .relay_host = "relay.test" },
    };
    try sub.ensureSubscription();

    // Randomized rkeys so we're not on a hardcoded happy path.
    var prng = std.Random.DefaultPrng.init(0xC0_FF_EE_42);
    const rand = prng.random();
    var rk1: [8]u8 = undefined;
    var rk2: [8]u8 = undefined;
    for (&rk1) |*ch| ch.* = "abcdef0123456789"[rand.intRangeLessThan(usize, 0, 16)];
    for (&rk2) |*ch| ch.* = "abcdef0123456789"[rand.intRangeLessThan(usize, 0, 16)];

    var p1: [40]u8 = undefined;
    var p2: [40]u8 = undefined;
    var p3: [40]u8 = undefined;
    const path1 = try std.fmt.bufPrint(&p1, "app.bsky.feed.post/{s}", .{rk1});
    const path2 = try std.fmt.bufPrint(&p2, "app.bsky.feed.like/{s}", .{rk2});
    const path3 = try std.fmt.bufPrint(&p3, "app.bsky.feed.post/{s}", .{rk1});

    const rec_post = "{\"$type\":\"app.bsky.feed.post\",\"text\":\"hi\",\"createdAt\":\"2026-06-01T00:00:00Z\"}";
    const rec_like = "{\"$type\":\"app.bsky.feed.like\",\"subject\":{\"uri\":\"at://did:plc:x/app.bsky.feed.post/y\"},\"createdAt\":\"2026-06-01T00:00:00Z\"}";

    const ops = [_]EncodeOp{
        .{ .action = "create", .path = path1, .record = rec_post },
        .{ .action = "create", .path = path2, .record = rec_like },
        // A bridged-collection delete now translates to an AP Delete
        // (post) — it is no longer skipped.
        .{ .action = "delete", .path = path3, .record = "" },
    };
    var msg_buf: [4096]u8 = undefined;
    const msg = try encodeCommitMessage(&msg_buf, 9001, "did:plc:multi", 1_717_000_000, &ops);

    const ingested = try sub.ingestEventBytes(msg);
    try testing.expectEqual(@as(u32, 3), ingested); // post + like + post-delete
    try testing.expectEqual(@as(i64, 9001), sub.cursor_seq);
}

test "R1: feed() decodes a real WS binary frame end-to-end" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var sc = core.clock.SimClock.init(1_718_000_000);
    var sub: Subscriber = .{
        .db = db,
        .clock = sc.clock(),
        .cfg = .{ .url = "ws://upstream.test", .enable = true, .relay_host = "relay.test" },
    };
    try sub.ensureSubscription();

    const ops = [_]EncodeOp{.{
        .action = "create",
        .path = "app.bsky.feed.post/wsframe",
        .record = "{\"$type\":\"app.bsky.feed.post\",\"text\":\"ws\",\"createdAt\":\"2026-06-10T00:00:00Z\"}",
    }};
    var msg_buf: [2048]u8 = undefined;
    const msg = try encodeCommitMessage(&msg_buf, 12345, "did:plc:wsuser", 1_718_000_000, &ops);

    var frame_buf: [2048]u8 = undefined;
    const framed = try frameMessage(msg, &frame_buf);
    var frame_mut: [2048]u8 = undefined;
    @memcpy(frame_mut[0..framed.len], framed);

    const ingested = try sub.feed(frame_mut[0..framed.len]);
    try testing.expectEqual(@as(u32, 1), ingested);
    try testing.expectEqual(@as(u64, 1), sub.stats.frames_seen.load(.monotonic));
}

fn logContains(db: *c.sqlite3, needle: []const u8) bool {
    var rows: [16]subscription.LogEntry = undefined;
    const n = subscription.listLog(db, 0, &rows) catch return false;
    for (rows[0..n]) |r| {
        if (std.mem.indexOf(u8, r.sourceId(), needle) != null) return true;
        if (std.mem.indexOf(u8, r.translatedId(), needle) != null) return true;
    }
    return false;
}

fn outboxPayloadContains(db: *c.sqlite3, needle: []const u8) bool {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT payload FROM ap_federation_outbox", -1, &stmt, null) != c.SQLITE_OK) return false;
    defer _ = c.sqlite3_finalize(stmt);
    var buf: [4096]u8 = undefined;
    while (c.sqlite3_step(stmt.?) == c.SQLITE_ROW) {
        const ptr = c.sqlite3_column_text(stmt, 0);
        const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
        const cap = @min(n, buf.len);
        if (ptr != null and cap > 0) {
            @memcpy(buf[0..cap], ptr[0..cap]);
            if (std.mem.indexOf(u8, buf[0..cap], needle) != null) return true;
        }
    }
    return false;
}

test "R1: upstream post DELETE → AP Delete logged + fanned to followers" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var sc = core.clock.SimClock.init(1_719_000_000);
    var sub: Subscriber = .{
        .db = db,
        .clock = sc.clock(),
        .cfg = .{ .url = "ws://upstream.test", .enable = true, .relay_host = "relay.test" },
    };
    try sub.ensureSubscription();

    const did = "did:plc:deleter";
    // First a create so the synthetic actor exists.
    const rec = "{\"$type\":\"app.bsky.feed.post\",\"text\":\"doomed\",\"createdAt\":\"2026-06-22T00:00:00Z\"}";
    const create_ops = [_]EncodeOp{.{ .action = "create", .path = "app.bsky.feed.post/del1", .record = rec }};
    var cb: [2048]u8 = undefined;
    _ = try sub.ingestEventBytes(try encodeCommitMessage(&cb, 10, did, 1_719_000_000, &create_ops));

    // Resolve the minted actor + add a follower so the Delete has
    // somewhere to go.
    var ab2: [1024]u8 = undefined;
    var a2 = Arena.init(&ab2);
    const minted_actor = (try plugin.identity_map.actorForDid(db, did, &a2)).?;
    try @import("followers.zig").add(db, sc.clock(), minted_actor, "https://m.example/users/peer/inbox", "", "fi-del");

    // Now the delete op.
    const del_ops = [_]EncodeOp{.{ .action = "delete", .path = "app.bsky.feed.post/del1", .record = "" }};
    var db_buf: [2048]u8 = undefined;
    const ingested = try sub.ingestEventBytes(try encodeCommitMessage(&db_buf, 11, did, 1_719_000_001, &del_ops));
    try testing.expectEqual(@as(u32, 1), ingested);

    try testing.expect(logContains(db, "[deleted]"));
    try testing.expect(outboxPayloadContains(db, "\"type\":\"Delete\""));
}

test "R1: upstream like DELETE → Undo{Like} fanned to followers" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var sc = core.clock.SimClock.init(1_719_100_000);
    var sub: Subscriber = .{
        .db = db,
        .clock = sc.clock(),
        .cfg = .{ .url = "ws://upstream.test", .enable = true, .relay_host = "relay.test" },
    };
    try sub.ensureSubscription();

    const did = "did:plc:unliker";
    const rec = "{\"$type\":\"app.bsky.feed.like\",\"subject\":{\"uri\":\"at://did:plc:x/app.bsky.feed.post/y\"},\"createdAt\":\"2026-06-22T00:00:00Z\"}";
    const create_ops = [_]EncodeOp{.{ .action = "create", .path = "app.bsky.feed.like/lk1", .record = rec }};
    var cb: [2048]u8 = undefined;
    _ = try sub.ingestEventBytes(try encodeCommitMessage(&cb, 20, did, 1_719_100_000, &create_ops));

    var ab2: [1024]u8 = undefined;
    var a2 = Arena.init(&ab2);
    const minted_actor = (try plugin.identity_map.actorForDid(db, did, &a2)).?;
    try @import("followers.zig").add(db, sc.clock(), minted_actor, "https://m.example/users/peer/inbox", "", "fi-unlike");

    const del_ops = [_]EncodeOp{.{ .action = "delete", .path = "app.bsky.feed.like/lk1", .record = "" }};
    var db_buf: [2048]u8 = undefined;
    const ingested = try sub.ingestEventBytes(try encodeCommitMessage(&db_buf, 21, did, 1_719_100_001, &del_ops));
    try testing.expectEqual(@as(u32, 1), ingested);

    try testing.expect(outboxPayloadContains(db, "\"type\":\"Undo\""));
    try testing.expect(outboxPayloadContains(db, "\"type\":\"Like\""));
}

test "R1: cursor resumes from persisted value on a fresh subscriber" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1);

    // First subscriber consumes up to seq 500 and persists.
    {
        var sub: Subscriber = .{
            .db = db,
            .clock = sc.clock(),
            .cfg = .{ .url = "ws://resume.test", .enable = true, .relay_host = "relay.test" },
        };
        try sub.ensureSubscription();
        const ops = [_]EncodeOp{.{
            .action = "create",
            .path = "app.bsky.feed.post/r",
            .record = "{\"$type\":\"app.bsky.feed.post\",\"text\":\"x\",\"createdAt\":\"2026-01-01T00:00:00Z\"}",
        }};
        var mb: [1024]u8 = undefined;
        const msg = try encodeCommitMessage(&mb, 500, "did:plc:resume", 1, &ops);
        _ = try sub.ingestEventBytes(msg);
    }

    // A fresh subscriber against the same URL loads the persisted cursor.
    var sub2: Subscriber = .{
        .db = db,
        .clock = sc.clock(),
        .cfg = .{ .url = "ws://resume.test", .enable = true, .relay_host = "relay.test" },
    };
    try sub2.ensureSubscription();
    try testing.expectEqual(@as(i64, 500), sub2.cursor_seq);
}
