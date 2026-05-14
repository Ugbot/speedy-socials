//! Per-subsystem error sets.
//!
//! Each subsystem declares its own error set so callers can pattern-match
//! exhaustively. Avoid `anyerror` outside test code.

pub const HttpError = error{
    MalformedRequestLine,
    MalformedHeader,
    HeaderTooLarge,
    TooManyHeaders,
    MethodTooLong,
    TargetTooLong,
    PayloadTooLarge,
    UnexpectedEof,
    NotFound,
    MethodNotAllowed,
    BadRequest,
    Unauthorized,
    Forbidden,
    Conflict,
    Internal,
    ConnectionLimitReached,
    ResponseBufferFull,
};

pub const StorageError = error{
    OpenFailed,
    PrepareFailed,
    BindFailed,
    StepFailed,
    NotFound,
    Conflict,
    BackpressureRejected,
    TooManyStatements,
};

pub const PluginError = error{
    TooManyPlugins,
    DuplicateName,
    NameTooLong,
    NotFound,
    VersionMismatch,
    AlreadyInitialized,
    RouteRegistrationFailed,
    SchemaRegistrationFailed,
};

pub const RouterError = error{
    TooManyRoutes,
    PatternTooLong,
    DuplicateRoute,
    NoMatch,
};

pub const FedError = error{
    SignatureMissing,
    SignatureMalformed,
    SignatureInvalid,
    KeyFetchFailed,
    UnknownActivityType,
    DeliveryFailed,
    OutboxFull,
};

pub const ApError = error{
    UnsupportedActivity,
    UnknownActor,
    BadObject,
    InboxRejected,
};

pub const AtpError = error{
    BadCid,
    BadTid,
    BadDid,
    BadCbor,
    // Syntax validators added by `protocols/atproto/syntax.zig`. They live
    // here rather than in their own set so callers (router, repo, relay)
    // can match a single error type.
    BadHandle,
    BadNsid,
    BadRkey,
    BadAtUri,
    BadMultibase,
    BadMulticodec,
    // Misc AT primitive failures.
    BufferTooSmall,
    NotImplemented,
    MstInvariant,
    CommitInvalid,
};
