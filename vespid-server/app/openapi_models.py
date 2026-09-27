"""Pydantic models for OpenAPI documentation.

These models describe request/response schemas for the Vespid Server API
endpoints. They are used by flask-openapi3 to generate the OpenAPI spec
and Swagger UI.
"""

from pydantic import BaseModel, Field


class EventMetadata(BaseModel):
    """Metadata attached to a security event."""

    detection_rule_name: str | None = None
    block_ttl_seconds: int | None = None
    action_taken: str | None = None
    event_kind: str | None = None
    threat_tag: str | None = None
    request_count: int | None = None
    reason: str | None = None


class SecurityEvent(BaseModel):
    """A single security event from a Vespid agent."""

    event_id: str = Field(description="Unique event identifier (UUID)")
    node_id: str = Field(description="Agent node identifier")
    source_ip: str = Field(description="Source IP address of the event")
    event_type: str = Field(description="Event type (e.g. NFT_ACTION, SSH_AUTH)")
    event_kind: str | None = Field(default=None, description="Event kind (e.g. block, fleet_block)")
    action_taken: str = Field(description="Action taken (BLOCKED, OBSERVED, UNBLOCKED)")
    timestamp: str = Field(description="ISO 8601 timestamp of the event")
    metadata: EventMetadata | None = Field(default=None, description="Event metadata")
    geo_data: dict | None = Field(default=None, description="GeoIP enrichment data")


class EventBatchRequest(BaseModel):
    """Batch of security events for ingestion."""

    events: list[SecurityEvent] = Field(
        min_length=1,
        max_length=100,
        description="Array of security events (1-100 per batch)",
    )


class RejectedEvent(BaseModel):
    """Details of a rejected event in a batch."""

    index: int = Field(description="Original index in the events array")
    event_id: str | None = Field(default=None, description="Event ID if available")
    errors: list[str] = Field(description="List of validation errors")


class EventBatchResponse(BaseModel):
    """Response from event batch ingestion."""

    accepted: int = Field(description="Number of events accepted")
    rejected: list[RejectedEvent] = Field(description="List of rejected events with errors")
    total: int = Field(description="Total number of events in the batch")


class EventBatchErrorResponse(BaseModel):
    """Error response when all events fail validation."""

    error: str = Field(description="Error code")
    message: str = Field(description="Human-readable error message")
    rejected: list[RejectedEvent] | None = Field(default=None, description="Rejected events")


class VerifyAPIKeyResponse(BaseModel):
    """Response from API key verification."""

    ok: bool = Field(description="Whether the key is valid")
    node_id: str = Field(description="Node ID restricted to this key")


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(description="ok or error")
    message: str | None = Field(default=None, description="Error message if status is error")


class FleetBlock(BaseModel):
    """A fleet-wide block entry."""

    id: int = Field(description="Block ID")
    source_ip: str = Field(description="Blocked IP address")
    originating_node_id: str = Field(description="Node that reported the block")
    event_type: str = Field(description="Event type that triggered the block")
    detection_rule: str = Field(description="Detection rule name")
    status: str = Field(description="Block status (active, expired, removed)")
    created_at: str = Field(description="ISO 8601 creation timestamp")
    expires_at: str | None = Field(default=None, description="ISO 8601 expiry timestamp")


class FleetBlockListResponse(BaseModel):
    """Paginated list of fleet blocks."""

    blocks: list[FleetBlock] = Field(description="List of fleet blocks")
    total: int = Field(description="Total number of matching blocks")
    page: int = Field(description="Current page number")
    per_page: int = Field(description="Items per page")
    total_pages: int = Field(description="Total number of pages")


class FleetBlockAddRequest(BaseModel):
    """Request to manually add a fleet block."""

    source_ip: str = Field(description="IP address to block")
    event_type: str = Field(default="manual", description="Event type")
    detection_rule: str = Field(default="manual", description="Detection rule name")
    block_ttl_seconds: int | None = Field(default=86400, description="Block duration in seconds")
    reason: str | None = Field(default=None, description="Reason for the block")


class IPIntelRecord(BaseModel):
    """IP intelligence record."""

    ip_address: str = Field(description="IP address")
    total_times_seen: int = Field(description="Total times this IP was seen")
    total_times_blocked: int = Field(description="Total times this IP was blocked")
    first_seen_at: str | None = Field(default=None, description="First seen timestamp")
    last_seen_at: str | None = Field(default=None, description="Last seen timestamp")
    geo_country: str | None = Field(default=None, description="Country code")
    asn: int | None = Field(default=None, description="Autonomous System Number")
    isp_organization: str | None = Field(default=None, description="ISP/organization name")
    threat_score: int | None = Field(default=None, description="Threat score (0-100)")
    repeat_offender: bool = Field(default=False, description="Whether this is a repeat offender")


class IPIntelQueryResponse(BaseModel):
    """Response from IP intel query."""

    records: list[IPIntelRecord] = Field(description="List of IP records")
    total: int = Field(description="Total number of matching records")
    page: int = Field(description="Current page number")
    per_page: int = Field(description="Items per page")


class EnrollmentRequest(BaseModel):
    """Agent enrollment request."""

    node_id: str = Field(description="Desired node identifier")
    hostname: str = Field(description="Host name of the agent")
    os_distro: str = Field(description="Linux distribution (e.g. ubuntu, rocky)")
    os_version: str = Field(description="OS version string")
    agent_version: str = Field(description="Vespid agent version")
    interfaces: list[dict] | None = Field(default=None, description="Network interfaces")


class EnrollmentStatusResponse(BaseModel):
    """Enrollment status response."""

    status: str = Field(description="pending, approved, rejected")
    node_id: str = Field(description="Node identifier")
    api_key: str | None = Field(default=None, description="API key (only when approved)")
    server_url: str | None = Field(default=None, description="Server URL (only when approved)")
    message: str | None = Field(default=None, description="Status message")


class CounterSnapshot(BaseModel):
    """Counter snapshot from an agent."""

    node_id: str = Field(description="Agent node identifier")
    timestamp: str = Field(description="ISO 8601 timestamp")
    counters: dict = Field(description="Counter name -> value mapping")


class HeartbeatResponse(BaseModel):
    """Response from agent heartbeat."""

    status: str = Field(description="ok")
    config_version: int | None = Field(default=None, description="Latest config version")
    rules_version: int | None = Field(default=None, description="Latest rules version")


# ── Path parameter models (used by flask-openapi3 to pass URL params) ───


class LabelNamePath(BaseModel):
    """Path parameter for label values proxy."""

    label_name: str = Field(description="Label name to query values for")


class AgentIdPath(BaseModel):
    """Path parameter for agent-specific endpoints."""

    agent_id: str = Field(description="Agent/node identifier")


class QueryIdPath(BaseModel):
    """Path parameter for saved query CRUD."""

    query_id: int = Field(description="Saved query ID")


class WatchIdPath(BaseModel):
    """Path parameter for logfile watch CRUD."""

    watch_id: int = Field(description="Logfile watch ID")


class WorkerIdPath(BaseModel):
    """Path parameter for synthetic worker endpoints."""

    worker_id: str = Field(description="Worker identifier")


class JobIdPath(BaseModel):
    """Path parameter for synthetic job endpoints."""

    job_id: int = Field(description="Job identifier")


class CheckIdPath(BaseModel):
    """Path parameter for synthetic check endpoints."""

    check_id: int = Field(description="Check identifier")


class RuleIdPath(BaseModel):
    """Path parameter for alert/rule endpoints."""

    rule_id: int = Field(description="Rule identifier")


class ChannelIdPath(BaseModel):
    """Path parameter for notification channel endpoints."""

    channel_id: int = Field(description="Channel identifier")


class SilenceIdPath(BaseModel):
    """Path parameter for silence endpoints."""

    silence_id: int = Field(description="Silence identifier")


class GroupIdPath(BaseModel):
    """Path parameter for monitoring group endpoints."""

    group_id: int = Field(description="Group identifier")


class ConditionIdPath(BaseModel):
    """Path parameter for group condition endpoints."""

    condition_id: int = Field(description="Condition identifier")


class EventIdPath(BaseModel):
    """Path parameter for alert event endpoints."""

    event_id: int = Field(description="Event identifier")


class ProfileIdPath(BaseModel):
    """Path parameter for config profile endpoints."""

    profile_id: int = Field(description="Profile identifier")


class AssignmentIdPath(BaseModel):
    """Path parameter for config assignment endpoints."""

    assignment_id: int = Field(description="Assignment identifier")


class VersionPath(BaseModel):
    """Path parameter for version history endpoints."""

    ver: int = Field(description="Version number")


class PackNamePath(BaseModel):
    """Path parameter for rule pack endpoints."""

    pack_name: str = Field(description="Pack name")


class PolicyIdPath(BaseModel):
    """Path parameter for policy endpoints."""

    policy_id: int = Field(description="Policy identifier")
