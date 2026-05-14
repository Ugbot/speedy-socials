//! zat - zig atproto primitives
//!
//! parsing and validation for AT Protocol string formats.
//! DID resolution for did:plc and did:web.

// syntax primitives
pub const Tid = @import("internal/syntax/tid.zig").Tid;
pub const Did = @import("internal/syntax/did.zig").Did;
pub const Handle = @import("internal/syntax/handle.zig").Handle;
pub const Nsid = @import("internal/syntax/nsid.zig").Nsid;
pub const Rkey = @import("internal/syntax/rkey.zig").Rkey;
pub const AtUri = @import("internal/syntax/at_uri.zig").AtUri;

// identity resolution
pub const DidDocument = @import("internal/identity/did_document.zig").DidDocument;
pub const DidResolver = @import("internal/identity/did_resolver.zig").DidResolver;
pub const HandleResolver = @import("internal/identity/handle_resolver.zig").HandleResolver;

// xrpc
pub const XrpcClient = @import("internal/xrpc/xrpc.zig").XrpcClient;

// json helpers
pub const json = @import("internal/xrpc/json.zig");

// crypto
pub const jwt = @import("internal/crypto/jwt.zig");
pub const Jwt = jwt.Jwt;
pub const multibase = @import("internal/crypto/multibase.zig");
pub const multicodec = @import("internal/crypto/multicodec.zig");
pub const Keypair = @import("internal/crypto/keypair.zig").Keypair;

// oauth
pub const oauth = @import("internal/oauth.zig");

// repo
pub const mst = @import("internal/repo/mst.zig");
pub const cbor = @import("internal/repo/cbor.zig");
pub const car = @import("internal/repo/car.zig");

// repo verification
pub const repo_verifier = @import("internal/repo/repo_verifier.zig");
pub const verifyRepo = repo_verifier.verifyRepo;
pub const VerifyResult = repo_verifier.VerifyResult;
pub const verifyCommitCar = repo_verifier.verifyCommitCar;
pub const CommitVerifyResult = repo_verifier.CommitVerifyResult;

// sync 1.1: commit diff verification
pub const MstOperation = mst.Operation;
pub const Commit = repo_verifier.Commit;
pub const loadCommitFromCAR = repo_verifier.loadCommitFromCAR;
pub const verifyCommitDiff = repo_verifier.verifyCommitDiff;
pub const CommitDiffResult = repo_verifier.CommitDiffResult;

// sync / streaming
const sync = @import("internal/streaming/sync.zig");
pub const CommitAction = sync.CommitAction;
pub const EventKind = sync.EventKind;
pub const AccountStatus = sync.AccountStatus;

// jetstream
pub const jetstream = @import("internal/streaming/jetstream.zig");
pub const JetstreamClient = jetstream.JetstreamClient;
pub const JetstreamEvent = jetstream.Event;

// firehose (raw CBOR event stream)
pub const firehose = @import("internal/streaming/firehose.zig");
pub const FirehoseClient = firehose.FirehoseClient;
pub const FirehoseEvent = firehose.Event;

// interop tests (test-only, references resolved by build.zig lazy dependency)
comptime {
    if (@import("builtin").is_test) {
        _ = @import("internal/testing/interop_tests.zig");
        _ = @import("internal/repo/repo_verifier.zig");
    }
}
