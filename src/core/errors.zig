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

pub const RelayError = error{
    /// A protocol record/activity arrived that we have no translator for.
    UnsupportedKind,
    /// Translator produced output that overflowed the caller-supplied arena.
    TranslationBufferTooSmall,
    /// AT record JSON did not parse / lacked required fields.
    BadAtRecord,
    /// AP activity JSON did not parse / lacked required fields.
    BadApActivity,
    /// The relay's sibling-lookup found neither `atproto` nor `activitypub`.
    /// Boot must register them BEFORE the relay plugin.
    SiblingPluginMissing,
    /// Identity-map upsert failed at the storage layer.
    IdentityMapFailed,
    /// Subscription state machine got an invalid transition.
    BadSubscriptionState,
    /// Subscription not found in the table.
    SubscriptionNotFound,
};

pub const ObsError = error{
    /// The metrics registry is full at compile-time-declared `max_metrics`.
    TooManyMetrics,
    /// A metric name was longer than `max_metric_name_bytes`.
    MetricNameTooLong,
    /// A metric help string was longer than `max_metric_help_bytes`.
    MetricHelpTooLong,
    /// A histogram was registered with too many bucket boundaries.
    TooManyBuckets,
    /// A histogram was registered with non-monotonic bucket boundaries.
    BucketsNotMonotonic,
    /// A metric with the same name + kind was already registered.
    DuplicateMetric,
    /// MetricId did not refer to a registered metric (or wrong kind).
    UnknownMetric,
    /// Wrong metric kind for the call (e.g. `observe` on a counter).
    WrongMetricKind,
    /// Output writer ran out of space while exporting Prometheus text.
    ExportBufferFull,
    /// Too many shutdown phases registered (`max_shutdown_phases`).
    TooManyPhases,
    /// Too many ready hooks registered (`max_health_hooks`).
    TooManyHooks,
    /// Phase / hook label longer than `max_phase_name_bytes`.
    LabelTooLong,
    /// A ready hook reported NotReady — `/readyz` returns 503.
    NotReady,
    /// Signal handler installation failed.
    SignalSetupFailed,
};
