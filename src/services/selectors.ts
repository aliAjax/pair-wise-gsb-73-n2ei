import type {
  ControlEvidence,
  CountersignAssessment,
  CountersignBlocker,
  CountersignBlockerKind,
  ReviewDecision,
  Risk,
  Severity,
  Threat,
  ThreatModelState,
  ValidationIssue,
  VersionDifference,
  VersionSnapshot,
} from '@/models/domain'

const TODAY = new Date('2026-09-29T00:00:00+08:00')

export const REQUIRED_ROLES = ['development', 'security', 'business'] as const

const ROLE_LABELS: Record<string, string> = {
  development: '开发负责人',
  security: '安全负责人',
  business: '业务负责人',
}

export const roleLabel = (role: string): string => ROLE_LABELS[role] ?? role

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

const ACTION_LABELS: Record<string, string> = {
  restrict: '限制访问',
  monitor: '持续监测',
  encrypt: '加密保护',
  isolate: '隔离处置',
  allow_with_condition: '有条件放行',
}

const DECISION_LABELS: Record<string, string> = {
  approved: '通过',
  accept: '有条件接受',
  degrade: '同意降级',
  evidence_required: '要求补证',
  rejected: '驳回',
}

export const decisionLabel = (decision?: string): string =>
  decision ? (DECISION_LABELS[decision] ?? decision) : '待提交'

const makeBlocker = (
  threatId: string,
  kind: CountersignBlockerKind,
  label: string,
  entityId: string,
  title: string,
  currentValue: string,
  detail: string,
  remediation: string,
): CountersignBlocker => ({
  id: `cs-${threatId}-${kind}-${entityId}`,
  kind,
  label,
  entityId,
  title,
  currentValue,
  detail,
  remediation,
})

const evidenceState = (item: ControlEvidence): string => {
  if (evidenceIsExpired(item)) return `${item.title} 已于 ${item.expiresAt} 到期`
  if (!item.valid) return `${item.title} 已被标记为失效`
  return `${item.title} 有效至 ${item.expiresAt}`
}

/**
 * 把三方意见、关联控制证据有效期、风险接受期限与缓解冲突放进同一次判断，
 * 只要存在任一阻塞项，该威胁的会签结论就不能成立。
 */
export const countersignBlockers = (
  state: ThreatModelState,
  threat: Threat,
): CountersignBlocker[] => {
  const blockers: CountersignBlocker[] = []
  const decisions = decisionsForThreat(state.decisions, threat.id, threat.revision)

  REQUIRED_ROLES.forEach((role) => {
    const decision = decisions.find((item) => item.role === role)
    if (!decision) {
      blockers.push(
        makeBlocker(
          threat.id,
          'missing_signature',
          '三方意见',
          role,
          `${roleLabel(role)}尚未会签`,
          '当前值：待提交',
          `v1.${threat.revision} 版本下缺少 ${roleLabel(role)} 的会签意见。`,
          `请 ${roleLabel(role)} 在会签中心提交意见后再核对。`,
        ),
      )
    } else if (decision.decision !== 'approved') {
      blockers.push(
        makeBlocker(
          threat.id,
          'decision_not_approved',
          '三方意见',
          decision.id,
          `${roleLabel(role)}意见未达成通过`,
          `当前值：${decisionLabel(decision.decision)}（${decision.actor}）`,
          `意见说明：${decision.comment || '未填写'}`,
          decision.decision === 'rejected'
            ? '该威胁已被驳回，需调整方案并重新提交三方意见。'
            : '需先落实该意见中的条件或补证要求，再由其重新给出“通过”意见。',
        ),
      )
    }
  })

  threat.controlIds.forEach((controlId) => {
    const control = state.controls.find((item) => item.id === controlId)
    if (!control) {
      blockers.push(
        makeBlocker(
          threat.id,
          'control_evidence_expired',
          '证据有效期',
          controlId,
          '关联控制已从当前模型移除',
          '当前值：控制不存在',
          '会签所依赖的控制在后续版本中被删除，结论失去依据。',
          '请重新关联有效控制并补充证据，或重新评估该威胁。',
        ),
      )
      return
    }
    const linkedEvidence = control.evidenceIds
      .map((id) => state.evidence.find((item) => item.id === id))
      .filter((item): item is ControlEvidence => Boolean(item))
    const validEvidence = linkedEvidence.filter((item) => item.valid && !evidenceIsExpired(item))
    const controlUnhealthy = control.status === 'failed' || control.status === 'degraded'
    if (validEvidence.length === 0 || controlUnhealthy) {
      const statusText =
        control.status === 'failed'
          ? '控制已失效'
          : control.status === 'degraded'
            ? '控制能力降级'
            : '控制状态有效'
      const evidenceText = linkedEvidence.length
        ? linkedEvidence.map(evidenceState).join('；')
        : '未登记任何控制证据'
      blockers.push(
        makeBlocker(
          threat.id,
          'control_evidence_expired',
          '证据有效期',
          control.id,
          `${control.name} 控制证据不满足会签条件`,
          `当前值：${statusText}；${evidenceText}`,
          '未找到未过期且状态有效的控制证据，无法证明控制在会签时点持续有效。',
          controlUnhealthy
            ? '先恢复控制能力，再重新采集未过期的有效证据。'
            : '请补充新的控制证据并登记到期日，待证据有效后重新核对。',
        ),
      )
    }
  })

  threat.riskIds.forEach((riskId) => {
    const risk = state.risks.find((item) => item.id === riskId)
    if (!risk) return
    if (risk.status === 'accepted' && isExpired(risk.acceptanceExpiresAt)) {
      blockers.push(
        makeBlocker(
          threat.id,
          'risk_acceptance_expired',
          '风险接受期限',
          risk.id,
          `${risk.code} 风险接受已过期`,
          `当前值：接受到期日 ${risk.acceptanceExpiresAt ?? '未设置'}（已过期）`,
          `接受条件：${risk.acceptanceCondition || '未填写'}`,
          '请在风险矩阵中续期风险接受（写明新的到期日与条件），或将风险转为处置并补充缓解证据。',
        ),
      )
    }
  })

  const conflictGroups = new Map<string, ThreatModelState['mitigations']>()
  state.mitigations
    .filter((task) => task.threatId === threat.id && task.conflictGroup)
    .forEach((task) => {
      const group = conflictGroups.get(task.conflictGroup as string) ?? []
      group.push(task)
      conflictGroups.set(task.conflictGroup as string, group)
    })
  conflictGroups.forEach((tasks, group) => {
    const actions = new Set(tasks.map((task) => task.action))
    if (actions.has('allow_with_condition') && (actions.has('restrict') || actions.has('isolate'))) {
      blockers.push(
        makeBlocker(
          threat.id,
          'mitigation_conflict',
          '缓解冲突',
          group,
          '同一威胁存在互斥缓解措施',
          `当前值：${tasks
            .map((task) => `${task.title}=${ACTION_LABELS[task.action] ?? task.action}`)
            .join('；')}`,
          '“有条件放行”与“限制访问/隔离处置”不能同时作为该威胁的处置方向。',
          '请统一处置方向（移除或调整互斥任务之一），确认后重新提交会签核对。',
        ),
      )
    }
  })

  return blockers
}

/**
 * 计算某条威胁在当前模型状态下的真实会签结论。
 * 历史意见（旧 revision）仍完整保留在 decisions 中，仅当前 revision 参与有效性判断。
 */
export const assessCountersign = (
  state: ThreatModelState,
  threat: Threat,
): CountersignAssessment => {
  const blockers = countersignBlockers(state, threat)
  const decisions = decisionsForThreat(state.decisions, threat.id, threat.revision)
  const rejected = decisions.some((decision) => decision.decision === 'rejected')
  const reviewStatus = rejected
    ? 'rejected'
    : blockers.length === 0
      ? 'approved'
      : 'in_review'
  return {
    threatId: threat.id,
    revision: threat.revision,
    effective: reviewStatus === 'approved',
    reviewStatus,
    blockers,
  }
}

export const assessAllCountersigns = (state: ThreatModelState): CountersignAssessment[] =>
  state.threats.map((threat) => assessCountersign(state, threat))

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

  const taskGroups = new Map<string, typeof state.mitigations>()
  state.mitigations.forEach((task) => {
    if (!task.conflictGroup) return
    const key = `${task.threatId}:${task.conflictGroup}`
    const group = taskGroups.get(key) ?? []
    group.push(task)
    taskGroups.set(key, group)
  })

  taskGroups.forEach((tasks) => {
    const actions = new Set(tasks.map((task) => task.action))
    const hasAllow = actions.has('allow_with_condition')
    const hasRestrictiveAction = actions.has('restrict') || actions.has('isolate')
    if (hasAllow && hasRestrictiveAction) {
      issues.push({
        id: `conflict-${tasks[0]?.conflictGroup ?? 'unknown'}`,
        kind: 'mitigation_conflict',
        severity: 'high',
        title: '缓解措施处置方向冲突',
        detail: tasks.map((task) => task.title).join('；'),
        entityId: tasks[0]?.threatId ?? '',
      })
    }
  })

  return issues.sort((a, b) => {
    const rank: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }
    return rank[b.severity] - rank[a.severity]
  })
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
  effectiveCountersigns: number
}

export const dashboardMetrics = (state: ThreatModelState): DashboardMetrics => {
  const assessments = assessAllCountersigns(state)
  return {
    components: state.components.length,
    threats: state.threats.length,
    critical: openCriticalThreats(state.threats),
    coverage: threatCoverage(state),
    openIssues: getValidationIssues(state).length,
    pendingReviews: assessments.filter((assessment) => assessment.reviewStatus !== 'approved').length,
    effectiveCountersigns: assessments.filter((assessment) => assessment.effective).length,
  }
}
