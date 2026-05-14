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
    MstInvariant,
    CommitInvalid,
};

pub const WsError = error{
    // Handshake — RFC 6455 §4
    HandshakeMissingUpgrade,
    HandshakeMissingConnection,
    HandshakeBadVersion,
    HandshakeMissingKey,
    HandshakeBadMethod,
    HandshakeBufferFull,
    // Frame codec — RFC 6455 §5
    FrameNeedMore,
    FrameReservedBitsSet,
    FrameUnknownOpcode,
    FrameControlTooLarge,
    FrameControlFragmented,
    FrameUnmasked,
    FrameMaskedFromServer,
    FrameTooLarge,
    FrameEncodeBufferTooSmall,
    // Message reassembly
    MessageTooLarge,
    UnexpectedContinuation,
    UnexpectedNonContinuation,
    InvalidUtf8,
    // Subscription registry
    RegistryExhausted,
    RegistryShardFull,
    SubscriptionNotFound,
    StreamKeyTooLong,
};
