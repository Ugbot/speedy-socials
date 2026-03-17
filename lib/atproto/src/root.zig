//! atproto - AT Protocol PDS server library
//!
//! Built on top of ZAT (zat.dev/zat) primitives, this library provides
//! the server-side logic for running an AT Protocol Personal Data Server (PDS).
//!
//! ZAT provides: syntax primitives, CBOR/CAR codecs, MST, crypto,
//! identity resolution, repo verification, firehose/jetstream clients, XRPC client.
//!
//! This library adds: storage abstraction, repository write path, authentication,
//! session management, XRPC server handlers, DID document serving, firehose production.

const std = @import("std");

// Re-export ZAT primitives for convenience
pub const zat = @import("zat");

// --- PDS server-side modules ---

// Core types
pub const xrpc = @import("xrpc.zig");
pub const XrpcInput = xrpc.XrpcInput;
pub const XrpcOutput = xrpc.XrpcOutput;
pub const XrpcError = xrpc.XrpcError;

pub const config = @import("config.zig");
pub const PdsConfig = config.PdsConfig;

// Storage
pub const storage = @import("storage.zig");
pub const Storage = storage.Storage;
pub const MemoryStorage = storage.MemoryStorage;

// Repository (write path)
pub const repo = @import("repo.zig");
pub const Repository = repo.Repository;

// Commit creation and signing
pub const commit = @import("commit.zig");
pub const Commit = commit.Commit;

// Record validation
pub const record = @import("record.zig");

// Authentication
pub const session = @import("auth/session.zig");
pub const jwt = @import("auth/jwt.zig");

// Identity (server-side)
pub const did_doc = @import("identity/did_doc.zig");
pub const well_known = @import("identity/well_known.zig");

// XRPC handlers (pure functions, no HTTP types)
pub const server_handlers = @import("handlers/server.zig");
pub const repo_handlers = @import("handlers/repo.zig");
pub const sync_handlers = @import("handlers/sync.zig");
pub const identity_handlers = @import("handlers/identity.zig");
pub const label_handlers = @import("handlers/label.zig");
pub const moderation_handlers = @import("handlers/moderation.zig");

// Router
pub const router = @import("router.zig");

test {
    _ = xrpc;
    _ = config;
    _ = storage;
    _ = repo;
    _ = commit;
    _ = record;
    _ = session;
    _ = jwt;
    _ = did_doc;
    _ = well_known;
    _ = server_handlers;
    _ = repo_handlers;
    _ = sync_handlers;
    _ = identity_handlers;
    _ = label_handlers;
    _ = moderation_handlers;
    _ = router;
}
