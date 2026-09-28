import type {
  ActorRole,
  ControlEvidence,
  CountersignBlocker,
  CountersignEvaluation,
  MitigationTask,
  ReviewDecision,
  Risk,
  RoleDecisionState,
  Severity,
  Threat,
  ThreatModelState,
  ValidationIssue,
  VersionDifference,
  VersionSnapshot,
} from '@/models/domain'

const TODAY = new Date('2026-09-29T00:00:00+08:00')

const REQUIRED_ROLES: ActorRole[] = ['development', 'security', 'business']

const ROLE_LABELS: Record<ActorRole, string> = {
  development: '开发负责人',
  security: '安全负责人',
  business: '业务负责人',
}

export const riskScore = (risk: Risk): number => risk.likelihood * risk.impact

export const riskLevel = (score: number): Severity => {
  if (score >= 20) return 'critical'
  if (score >= 12) return 'high'
  if (score >= 6) return 'medium'
  return 'low'
}

export const isExpired = (date?: string): boolean =>
  Boolean(date && new Date(`${date}T23:59:59+08:00`).getTime() < TODAY.getTime())

export const evidenceIsExpired = (evidence: ControlEvidence): boolean => isExpired(evidence.expiresAt)

export const getValidationIssues = (state: ThreatModelState): ValidationIssue[] => {
  const issues: ValidationIssue[] = []
  const coveredComponentIds = new Set(state.threats.flatMap((threat) => threat.componentIds))
  const coveredFlowIds = new Set(state.threats.flatMap((threat) => threat.flowIds))

  state.components
    .filter((component) => !coveredComponentIds.has(component.id))
    .forEach((component) => {
      issues.push({
        id: `coverage-component-${component.id}`,
        kind: 'uncovered_component',
        severity: component.criticality,
        title: `${component.name} 尚无关联威胁`,
        detail: '该组件位于建模边界内，但当前威胁清单没有覆盖它。',
        entityId: component.id,
      })
    })

  state.flows
    .filter((flow) => !coveredFlowIds.has(flow.id))
    .forEach((flow) => {
      issues.push({
        id: `coverage-flow-${flow.id}`,
        kind: 'uncovered_component',
        severity: flow.crossesTrustBoundary ? 'high' : 'medium',
        title: `${flow.name} 尚无关联威胁`,
        detail: '该数据流未进入威胁分析，请确认是否需要补充威胁场景。',
        entityId: flow.id,
      })
    })

  state.controls
    .filter((control) => control.status === 'failed' || control.status === 'degraded')
    .forEach((control) => {
      issues.push({
        id: `control-${control.id}`,
        kind: 'control_failed',
        severity: control.status === 'failed' ? 'critical' : 'high',
        title: `${control.name} 控制${control.status === 'failed' ? '已失效' : '能力降级'}`,
        detail: '控制状态低于设计目标，相关缓解措施必须重新验证。',
        entityId: control.id,
      })
    })

  state.controls
    .filter((control) => {
      if (control.evidenceIds.length === 0) return true
      const validEvidence = control.evidenceIds
        .map((id) => state.evidence.find((item) => item.id === id))
        .filter((item): item is ControlEvidence => Boolean(item))
        .filter((item) => item.valid && !evidenceIsExpired(item))
      return validEvidence.length === 0
    })
    .forEach((control) => {
      issues.push({
        id: `evidence-${control.id}`,
        kind: 'missing_evidence',
        severity: control.status === 'planned' ? 'medium' : 'high',
        title: `${control.name} 缺少有效证据`,
        detail: '未找到未过期且状态有效的控制证据，暂不能判定控制持续有效。',
        entityId: control.id,
      })
    })

  state.risks
    .filter((risk) => risk.status === 'accepted' && isExpired(risk.acceptanceExpiresAt))
    .forEach((risk) => {
      issues.push({
        id: `expired-${risk.id}`,
        kind: 'risk_acceptance_expired',
        severity: riskLevel(riskScore(risk)),
        title: `${risk.code} 风险接受已过期`,
        detail: `接受到期日为 ${risk.acceptanceExpiresAt ?? '未设置'}，需要重新评审或转为处置。`,
        entityId: risk.id,
      })
    })

  state.threats.forEach((threat) => {
    getMitigationConflicts(state.mitigations, threat.id).forEach((conflict) => {
      issues.push({
        id: `conflict-${conflict.group}`,
        kind: 'mitigation_conflict',
        severity: 'high',
        title: '缓解措施处置方向冲突',
        detail: conflict.tasks.map((task) => task.title).join('；'),
        entityId: threat.id,
      })
    })
  })

  return issues.sort((a, b) => {
    const rank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }
    return rank[b.severity] - rank[a.severity]
  })
}

export interface MitigationConflict {
  group: string
  threatId: string
  tasks: MitigationTask[]
}

/**
 * 找出同一威胁、同一冲突组下同时存在"限制/隔离"与"有条件放行"的互斥组合。
 */
export const getMitigationConflicts = (
  mitigations: MitigationTask[],
  threatId: string,
): MitigationConflict[] => {
  const groups = new Map<string, MitigationTask[]>()
  mitigations
    .filter((task) => task.threatId === threatId && task.conflictGroup)
    .forEach((task) => {
      const key = task.conflictGroup as string
      groups.set(key, [...(groups.get(key) ?? []), task])
    })

  const conflicts: MitigationConflict[] = []
  groups.forEach((tasks, group) => {
    const actions = new Set(tasks.map((task) => task.action))
    const hasAllow = actions.has('allow_with_condition')
    const hasRestrictiveAction = actions.has('restrict') || actions.has('isolate')
    if (hasAllow && hasRestrictiveAction) {
      conflicts.push({ group, threatId, tasks })
    }
  })
  return conflicts
}

const CONTROL_STATUS_LABELS: Record<string, string> = {
  effective: '有效',
  degraded: '能力降级',
  failed: '已失效',
  planned: '计划中',
}

const MITIGATION_ACTION_LABELS: Record<MitigationTask['action'], string> = {
  restrict: '限制访问',
  monitor: '持续监测',
  encrypt: '加密保护',
  isolate: '隔离处置',
  allow_with_condition: '有条件放行',
}

const summarizeEvidence = (
  state: ThreatModelState,
  evidenceIds: string[],
): { valid: ControlEvidence[]; expired: ControlEvidence[]; invalid: ControlEvidence[]; missing: string[] } => {
  const valid: ControlEvidence[] = []
  const expired: ControlEvidence[] = []
  const invalid: ControlEvidence[] = []
  const missing: string[] = []
  evidenceIds.forEach((id) => {
    const item = state.evidence.find((evidence) => evidence.id === id)
    if (!item) {
      missing.push(id)
    } else if (evidenceIsExpired(item)) {
      expired.push(item)
    } else if (!item.valid) {
      invalid.push(item)
    } else {
      valid.push(item)
    }
  })
  return { valid, expired, invalid, missing }
}

const block = (item: Omit<CountersignBlocker, 'id'>, index: number): CountersignBlocker => ({
  ...item,
  id: `${item.kind}-${item.entityId}-${index}`,
})

/**
 * 会签有效性核对：在同一次判断中同时校验
 * 1. 开发、安全、业务三方意见（齐备性、驳回、要求补证、接受/降级是否有有效风险接受支撑）；
 * 2. 威胁关联控制的状态与证据有效期；
 * 3. 关联风险的接受期限；
 * 4. 同一威胁下的互斥缓解措施。
 *
 * 任意一项构成阻塞都不会得到 approved 结论，并返回具体条目、当前值与待补动作。
 */
export const evaluateCountersign = (
  state: ThreatModelState,
  threat: Threat,
  now: Date = TODAY,
): CountersignEvaluation => {
  const blockers: CountersignBlocker[] = []
  const decisions = decisionsForThreat(state.decisions, threat.id, threat.revision)
  const roleStates: (RoleDecisionState | null)[] = REQUIRED_ROLES.map((role) => {
    const decision = decisions.find((item) => item.role === role)
    return decision
      ? {
          role,
          actor: decision.actor,
          decision: decision.decision,
          comment: decision.comment,
          createdAt: decision.createdAt,
        }
      : null
  })

  // 1. 三方意见
  REQUIRED_ROLES.forEach((role) => {
    const decision = decisions.find((item) => item.role === role)
    if (!decision) {
      blockers.push(
        block(
          {
            kind: 'role_missing',
            category: 'opinion',
            severity: 'high',
            subject: ROLE_LABELS[role],
            title: `${ROLE_LABELS[role]}尚未在 v1.${threat.revision} 提交会签意见`,
            currentValue: '待提交',
            requiredAction: `请${ROLE_LABELS[role]}在会签中心提交当前修订的会签意见`,
            entityId: `${threat.id}:${role}`,
          },
          blockers.length,
        ),
      )
    } else if (decision.decision === 'rejected') {
      blockers.push(
        block(
          {
            kind: 'rejected',
            category: 'opinion',
            severity: 'critical',
            subject: `${ROLE_LABELS[role]}（${decision.actor}）`,
            title: `${ROLE_LABELS[role]}已驳回该威胁`,
            currentValue: `驳回：${decision.comment || '未填写意见'}`,
            requiredAction: '按驳回意见整改后，由该角色重新提交会签意见',
            entityId: decision.id,
          },
          blockers.length,
        ),
      )
    } else if (decision.decision === 'evidence_required') {
      blockers.push(
        block(
          {
            kind: 'evidence_required',
            category: 'opinion',
            severity: 'high',
            subject: `${ROLE_LABELS[role]}（${decision.actor}）`,
            title: `${ROLE_LABELS[role]}要求补充证据`,
            currentValue: `要求补证：${decision.comment || '未填写补证要求'}`,
            requiredAction: '补齐要求的控制证据并确认有效后，由该角色重新确认会签',
            entityId: decision.id,
          },
          blockers.length,
        ),
      )
    }
  })

  const hasAcceptOrDegrade = decisions.some(
    (decision) => decision.decision === 'accept' || decision.decision === 'degrade',
  )

  // 2. 控制状态与证据有效期
  threat.controlIds.forEach((controlId) => {
    const control = state.controls.find((item) => item.id === controlId)
    if (!control) return
    if (control.status === 'failed' || control.status === 'degraded') {
      blockers.push(
        block(
          {
            kind: 'control_failed',
            category: 'evidence',
            severity: control.status === 'failed' ? 'critical' : 'high',
            subject: control.name,
            title: `控制「${control.name}」${CONTROL_STATUS_LABELS[control.status]}`,
            currentValue: `控制状态：${CONTROL_STATUS_LABELS[control.status]}（${control.owner}）`,
            requiredAction: '恢复控制至设计目标并重新验证，再提交会签',
            entityId: control.id,
          },
          blockers.length,
        ),
      )
    }

    if (control.evidenceIds.length === 0) {
      blockers.push(
        block(
          {
            kind: 'evidence_missing',
            category: 'evidence',
            severity: 'high',
            subject: control.name,
            title: `控制「${control.name}」未登记任何证据`,
            currentValue: '证据数量：0',
            requiredAction: `在控制证据页登记「${control.name}」的有效测试或配置证据`,
            entityId: control.id,
          },
          blockers.length,
        ),
      )
      return
    }

    const summary = summarizeEvidence(state, control.evidenceIds)
    if (summary.valid.length > 0) return

    const details = [
      ...summary.expired.map((item) => `${item.title}（到期日 ${item.expiresAt}）`),
      ...summary.invalid.map((item) => `${item.title}（${item.reference}，状态已失效）`),
      ...summary.missing.map((id) => `${id}（证据记录缺失）`),
    ].join('；')

    if (summary.expired.length > 0) {
      const newest = summary.expired.slice().sort((a, b) => b.expiresAt.localeCompare(a.expiresAt))[0]
      blockers.push(
        block(
          {
            kind: 'evidence_expired',
            category: 'evidence',
            severity: 'high',
            subject: control.name,
            title: `控制「${control.name}」证据已到期`,
            currentValue: `最近证据到期日：${newest?.expiresAt ?? '未知'}（核对基准日 ${now
              .toISOString()
              .slice(0, 10)}）；${details}`,
            requiredAction: `重新采集「${control.name}」证据并保证到期日晚于当前日期`,
            entityId: control.id,
          },
          blockers.length,
        ),
      )
    } else if (summary.invalid.length > 0) {
      blockers.push(
        block(
          {
            kind: 'evidence_invalid',
            category: 'evidence',
            severity: 'high',
            subject: control.name,
            title: `控制「${control.name}」证据状态失效`,
            currentValue: details,
            requiredAction: '复核失效原因，重新出具状态有效的控制证据',
            entityId: control.id,
          },
          blockers.length,
        ),
      )
    } else {
      blockers.push(
        block(
          {
            kind: 'evidence_missing',
            category: 'evidence',
            severity: 'high',
            subject: control.name,
            title: `控制「${control.name}」关联证据记录缺失`,
            currentValue: details,
            requiredAction: '补登关联证据或修正控制的证据引用',
            entityId: control.id,
          },
          blockers.length,
        ),
      )
    }
  })

  // 3. 风险接受期限
  const acceptedRisks = threat.riskIds
    .map((id) => state.risks.find((risk) => risk.id === id))
    .filter((risk): risk is Risk => Boolean(risk))
    .filter((risk) => risk.status === 'accepted')

  acceptedRisks.forEach((risk) => {
    if (!risk.acceptanceExpiresAt) {
      blockers.push(
        block(
          {
            kind: 'acceptance_missing',
            category: 'acceptance',
            severity: 'high',
            subject: `${risk.code} ${risk.title}`,
            title: `风险 ${risk.code} 已接受但未设定期限`,
            currentValue: '接受到期日：未设置',
            requiredAction: '补录风险接受到期日与接受条件，或转为处置/关闭',
            entityId: risk.id,
          },
          blockers.length,
        ),
      )
    } else if (isExpired(risk.acceptanceExpiresAt)) {
      blockers.push(
        block(
          {
            kind: 'acceptance_expired',
            category: 'acceptance',
            severity: riskLevel(riskScore(risk)) === 'critical' ? 'critical' : 'high',
            subject: `${risk.code} ${risk.title}`,
            title: `风险 ${risk.code} 的风险接受已过期`,
            currentValue: `接受到期日：${risk.acceptanceExpiresAt}（已过期，核对基准日 ${now
              .toISOString()
              .slice(0, 10)}）`,
            requiredAction: '重新评审风险接受并设新期限，或落实缓解措施后关闭风险',
            entityId: risk.id,
          },
          blockers.length,
        ),
      )
    }
  })

  const hasValidAcceptedRisk = acceptedRisks.some(
    (risk) => risk.acceptanceExpiresAt && !isExpired(risk.acceptanceExpiresAt),
  )
  // 仅当存在接受/降级意见且完全没有"已接受"风险记录时单列；过期/未设期限的情况已由具体条目覆盖。
  if (hasAcceptOrDegrade && acceptedRisks.length === 0 && !hasValidAcceptedRisk) {
    blockers.push(
      block(
        {
          kind: 'acceptance_missing',
          category: 'acceptance',
          severity: 'high',
          subject: threat.code,
          title: '存在接受/降级会签意见，但缺少风险接受记录支撑',
          currentValue: '关联风险中无"已接受"记录',
          requiredAction: '在风险矩阵中完成带期限的风险接受，或改会签意见为通过/驳回',
          entityId: threat.id,
        },
        blockers.length,
      ),
    )
  }

  // 4. 缓解冲突
  getMitigationConflicts(state.mitigations, threat.id).forEach((conflict) => {
    blockers.push(
      block(
        {
          kind: 'mitigation_conflict',
          category: 'conflict',
          severity: 'high',
          subject: `冲突组 ${conflict.group}`,
          title: '同一威胁下存在互斥缓解措施',
          currentValue: conflict.tasks
            .map((task) => `${task.title}（${MITIGATION_ACTION_LABELS[task.action]}）`)
            .join('；'),
          requiredAction: '在缓解任务中统一处置方向，移除"限制/隔离"与"有条件放行"的互斥组合',
          entityId: threat.id,
        },
        blockers.length,
      ),
    )
  })

  const severityRank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }
  const categoryRank: CountersignBlocker['category'][] = ['opinion', 'evidence', 'acceptance', 'conflict']
  blockers.sort((a, b) => {
    const rankDiff = severityRank[b.severity] - severityRank[a.severity]
    if (rankDiff !== 0) return rankDiff
    return categoryRank.indexOf(a.category) - categoryRank.indexOf(b.category)
  })

  const hasRejection = blockers.some((item) => item.kind === 'rejected')
  const rolesMissing = blockers.filter((item) => item.kind === 'role_missing').length
  const objectiveBlockers = blockers.filter(
    (item) => item.kind !== 'role_missing' && item.kind !== 'rejected',
  )

  let outcome: CountersignEvaluation['outcome']
  if (hasRejection) {
    outcome = 'rejected'
  } else if (rolesMissing === 0 && objectiveBlockers.length > 0) {
    outcome = 'blocked'
  } else if (rolesMissing > 0) {
    outcome = 'in_review'
  } else if (objectiveBlockers.length > 0) {
    outcome = 'blocked'
  } else {
    outcome = 'approved'
  }

  return {
    threatId: threat.id,
    revision: threat.revision,
    outcome,
    blockers,
    roleStates,
    decisions,
    checkedAt: now.toISOString(),
  }
}

/** 会签核对结论的中文展示 */
export const countersignOutcomeLabel = (outcome: CountersignEvaluation['outcome']): string => {
  switch (outcome) {
    case 'approved':
      return '会签有效'
    case 'blocked':
      return '会签阻塞'
    case 'rejected':
      return '会签驳回'
    case 'in_review':
      return '会签中'
  }
}

export const decisionsForThreat = (
  decisions: ReviewDecision[],
  threatId: string,
  revision: number,
): ReviewDecision[] =>
  decisions.filter((decision) => decision.threatId === threatId && decision.revision === revision)

export const reviewProgress = (decisions: ReviewDecision[]): number => {
  const roles = new Set(decisions.map((decision) => decision.role))
  return Math.round((roles.size / 3) * 100)
}

export const compareSnapshots = (from: VersionSnapshot, to: VersionSnapshot): VersionDifference => {
  const compare = (
    category: string,
    before: string[],
    after: string[],
  ): { added: VersionDifference['added']; removed: VersionDifference['removed'] } => {
    const beforeSet = new Set(before)
    const afterSet = new Set(after)
    return {
      added: after.filter((id) => !beforeSet.has(id)).map((id) => ({ category, id })),
      removed: before.filter((id) => !afterSet.has(id)).map((id) => ({ category, id })),
    }
  }

  const componentDiff = compare('组件', from.componentIds, to.componentIds)
  const flowDiff = compare('数据流', from.flowIds, to.flowIds)
  const threatDiff = compare('威胁', from.threatIds, to.threatIds)
  const controlDiff = compare('控制', from.controlIds, to.controlIds)
  const riskDiff = compare('风险', from.riskIds, to.riskIds)
  const affectedBefore = new Set(from.affectedThreatIds)
  const affectedAfter = new Set(to.affectedThreatIds)

  return {
    added: [
      ...componentDiff.added,
      ...flowDiff.added,
      ...threatDiff.added,
      ...controlDiff.added,
      ...riskDiff.added,
    ],
    removed: [
      ...componentDiff.removed,
      ...flowDiff.removed,
      ...threatDiff.removed,
      ...controlDiff.removed,
      ...riskDiff.removed,
    ],
    changed: [
      `受影响威胁：${from.affectedThreatIds.length} → ${to.affectedThreatIds.length}`,
      `新增进入审核：${[...affectedAfter].filter((id) => !affectedBefore.has(id)).join('、') || '无'}`,
      `退出审核：${[...affectedBefore].filter((id) => !affectedAfter.has(id)).join('、') || '无'}`,
      `版本说明：${to.notes || '未填写'}`,
    ],
  }
}

export const threatCoverage = (state: ThreatModelState): number => {
  if (state.components.length === 0) return 100
  const covered = new Set(state.threats.flatMap((threat) => threat.componentIds))
  return Math.round((covered.size / state.components.length) * 100)
}

export const openCriticalThreats = (threats: Threat[]): number =>
  threats.filter((threat) => threat.severity === 'critical' && threat.status !== 'mitigated').length

export interface DashboardMetrics {
  components: number
  threats: number
  critical: number
  coverage: number
  openIssues: number
  pendingReviews: number
}

export const dashboardMetrics = (state: ThreatModelState): DashboardMetrics => ({
  components: state.components.length,
  threats: state.threats.length,
  critical: openCriticalThreats(state.threats),
  coverage: threatCoverage(state),
  openIssues: getValidationIssues(state).length,
  pendingReviews: state.threats.filter((threat) => {
    if (threat.reviewStatus === 'draft') return false
    const outcome = evaluateCountersign(state, threat).outcome
    return outcome === 'in_review' || outcome === 'blocked'
  }).length,
})
