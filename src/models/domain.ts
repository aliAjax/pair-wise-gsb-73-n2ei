export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type ReviewStatus = 'draft' | 'in_review' | 'approved' | 'rejected' | 'blocked'
export type ThreatStatus = 'open' | 'mitigating' | 'mitigated' | 'accepted'
export type ControlStatus = 'effective' | 'degraded' | 'failed' | 'planned'
export type ActorRole = 'development' | 'security' | 'business'
export type DecisionType = 'accept' | 'degrade' | 'evidence_required' | 'approved' | 'rejected'

export interface SystemBoundary {
  id: string
  name: string
  description: string
  owner: string
  inScope: string
  outOfScope: string
}

export interface TrustZone {
  id: string
  name: string
  level: 'internet' | 'dmz' | 'internal' | 'restricted'
  description: string
}

export interface ArchitectureComponent {
  id: string
  name: string
  type: 'service' | 'asset' | 'data_store' | 'gateway' | 'client'
  zoneId: string
  criticality: Severity
  owner: string
  description: string
}

export interface ExternalDependency {
  id: string
  name: string
  vendor: string
  purpose: string
  dataClass: 'public' | 'internal' | 'confidential' | 'restricted'
  owner: string
  status: 'active' | 'review_due' | 'retired'
}

export interface DataFlow {
  id: string
  name: string
  sourceId: string
  targetId: string
  protocol: string
  dataClass: 'public' | 'internal' | 'confidential' | 'restricted'
  crossesTrustBoundary: boolean
  description: string
}

export interface ControlEvidence {
  id: string
  controlId: string
  title: string
  kind: 'test' | 'config' | 'ticket' | 'scan' | 'attestation'
  reference: string
  collectedAt: string
  expiresAt: string
  owner: string
  valid: boolean
}

export interface SecurityControl {
  id: string
  name: string
  type: 'preventive' | 'detective' | 'corrective'
  status: ControlStatus
  owner: string
  componentId: string
  description: string
  evidenceIds: string[]
}

export interface AttackPath {
  id: string
  name: string
  entryPoint: string
  target: string
  steps: string[]
  likelihood: 1 | 2 | 3 | 4 | 5
}

export interface Risk {
  id: string
  code: string
  title: string
  likelihood: 1 | 2 | 3 | 4 | 5
  impact: 1 | 2 | 3 | 4 | 5
  status: 'open' | 'mitigating' | 'accepted' | 'closed'
  owner: string
  acceptanceExpiresAt?: string
  acceptanceCondition?: string
}

export interface Threat {
  id: string
  code: string
  title: string
  category: 'spoofing' | 'tampering' | 'repudiation' | 'information_disclosure' | 'denial_of_service' | 'elevation'
  description: string
  severity: Severity
  status: ThreatStatus
  componentIds: string[]
  flowIds: string[]
  externalDependencyIds: string[]
  attackPathIds: string[]
  controlIds: string[]
  riskIds: string[]
  reviewStatus: ReviewStatus
  revision: number
}

export interface MitigationTask {
  id: string
  threatId: string
  title: string
  owner: string
  dueAt: string
  status: 'todo' | 'in_progress' | 'verifying' | 'done'
  action: 'restrict' | 'monitor' | 'encrypt' | 'isolate' | 'allow_with_condition'
  detail: string
  evidenceIds: string[]
  conflictGroup?: string
}

export interface ReviewDecision {
  id: string
  threatId: string
  actor: string
  role: ActorRole
  decision: DecisionType
  comment: string
  createdAt: string
  revision: number
}

export interface VersionSnapshot {
  id: string
  revision: number
  label: string
  createdAt: string
  author: string
  notes: string
  threatIds: string[]
  componentIds: string[]
  flowIds: string[]
  controlIds: string[]
  riskIds: string[]
  affectedThreatIds: string[]
}

export interface AuditEvent {
  id: string
  entityType: string
  entityId: string
  action: string
  actor: string
  createdAt: string
  detail: string
}

export interface ThreatModelState {
  boundary: SystemBoundary
  zones: TrustZone[]
  components: ArchitectureComponent[]
  dependencies: ExternalDependency[]
  flows: DataFlow[]
  controls: SecurityControl[]
  evidence: ControlEvidence[]
  threats: Threat[]
  attackPaths: AttackPath[]
  risks: Risk[]
  mitigations: MitigationTask[]
  decisions: ReviewDecision[]
  versions: VersionSnapshot[]
  audit: AuditEvent[]
  currentRevision: number
}

export interface ValidationIssue {
  id: string
  kind: 'uncovered_component' | 'control_failed' | 'risk_acceptance_expired' | 'mitigation_conflict' | 'missing_evidence'
  severity: Severity
  title: string
  detail: string
  entityId: string
}

export interface VersionChange {
  category: string
  id: string
}

export interface VersionDifference {
  added: VersionChange[]
  removed: VersionChange[]
  changed: string[]
}

export type CountersignBlockerKind =
  | 'role_missing'
  | 'rejected'
  | 'evidence_required'
  | 'control_failed'
  | 'evidence_expired'
  | 'evidence_invalid'
  | 'evidence_missing'
  | 'acceptance_expired'
  | 'acceptance_missing'
  | 'mitigation_conflict'

export type CountersignBlockerCategory =
  | 'opinion'
  | 'evidence'
  | 'acceptance'
  | 'conflict'

/**
 * 会签有效性核对阻塞项。一次核对同时覆盖三方意见、控制证据有效期、
 * 风险接受期限与缓解冲突，任何一项不满足都不能得到通过结论。
 */
export interface CountersignBlocker {
  id: string
  kind: CountersignBlockerKind
  category: CountersignBlockerCategory
  severity: Severity
  /** 被核对的对象名称，例如控制名、风险编号、会签角色 */
  subject: string
  /** 问题描述 */
  title: string
  /** 当前值（证据/接受期限/意见的真实状态） */
  currentValue: string
  /** 需要补齐的具体动作 */
  requiredAction: string
  entityId: string
}

/** 三方中某个角色在当前修订下的会签情况 */
export interface RoleDecisionState {
  role: ActorRole
  actor: string
  decision: DecisionType
  comment: string
  createdAt: string
}

/**
 * 单条威胁的会签有效性核对结果：
 * - approved：三方齐备且无客观阻塞项
 * - rejected：存在驳回意见
 * - blocked：三方已签完或无需继续等待，但仍有客观阻塞项
 * - in_review：三方尚未签完，且暂未出现阻塞结论
 */
export type CountersignOutcome = 'approved' | 'in_review' | 'blocked' | 'rejected'

export interface CountersignEvaluation {
  threatId: string
  revision: number
  outcome: CountersignOutcome
  blockers: CountersignBlocker[]
  roleStates: (RoleDecisionState | null)[]
  decisions: ReviewDecision[]
  checkedAt: string
}
