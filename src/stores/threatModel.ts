import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type {
  ActorRole,
  AuditEvent,
  CountersignEvaluation,
  DecisionType,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import { createId, loadState, resetState, saveState } from '@/services/repository'
import {
  countersignOutcomeLabel,
  dashboardMetrics,
  decisionsForThreat,
  evaluateCountersign,
  getValidationIssues,
  isExpired,
  reviewProgress,
} from '@/services/selectors'

type CollectionKey =
  | 'zones'
  | 'components'
  | 'dependencies'
  | 'flows'
  | 'controls'
  | 'evidence'
  | 'threats'
  | 'attackPaths'
  | 'risks'
  | 'mitigations'
  | 'decisions'

interface IdentifiedEntity {
  id: string
}

export const useThreatModelStore = defineStore('threat-model', () => {
  const data = ref<ThreatModelState>(loadState())
  const lastSavedAt = ref(new Date().toISOString())

  const metrics = computed(() => dashboardMetrics(data.value))
  const issues = computed(() => getValidationIssues(data.value))

  /**
   * 每条威胁当前修订的会签有效性核对结果。证据到期、风险接受过期、
   * 缓解冲突或三方意见变化都会实时反映，不再依赖曾经落库的 reviewStatus。
   */
  const countersigns = computed(() => {
    const map = new Map<string, CountersignEvaluation>()
    data.value.threats.forEach((threat) => {
      map.set(threat.id, evaluateCountersign(data.value, threat))
    })
    return map
  })

  const evaluationFor = (threatId: string): CountersignEvaluation | undefined =>
    countersigns.value.get(threatId)

  const pendingReviews = computed(() =>
    data.value.threats.filter((threat) => {
      if (threat.reviewStatus === 'draft') return false
      return ['in_review', 'blocked'].includes(evaluationFor(threat.id)?.outcome ?? 'in_review')
    }),
  )

  /**
   * 依据统一核对结果回写审核状态：任何过期/冲突/驳回场景都不允许保持 approved。
   * 只更新内存状态，避免在持久化流程中递归写盘。
   */
  const reconcileReviewStatuses = (): void => {
    data.value.threats.forEach((threat) => {
      if (threat.reviewStatus === 'draft') return
      threat.reviewStatus = evaluationFor(threat.id)?.outcome ?? threat.reviewStatus
    })
  }

  const persist = (): void => {
    reconcileReviewStatuses()
    saveState(data.value)
    lastSavedAt.value = new Date().toISOString()
  }

  // 载入历史仓库后立即核对一次：曾经落库的 approved 若已过期/冲突，页面不再按已通过展示。
  reconcileReviewStatuses()

  const appendAudit = (
    entityType: string,
    entityId: string,
    action: string,
    detail: string,
  ): void => {
    const event: AuditEvent = {
      id: createId('aud'),
      entityType,
      entityId,
      action,
      actor: '当前用户',
      createdAt: new Date().toISOString(),
      detail,
    }
    data.value.audit.unshift(event)
  }

  const saveEntity = (collection: CollectionKey, item: IdentifiedEntity): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === item.id)
    if (index >= 0) {
      target[index] = item
    } else {
      target.unshift(item)
    }
    const label = 'name' in item && typeof item.name === 'string' ? item.name : item.id
    appendAudit(collection, item.id, index >= 0 ? '更新' : '新增', `${label} 已保存`)
    persist()
  }

  const removeEntity = (collection: CollectionKey, id: string): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === id)
    if (index < 0) return
    target.splice(index, 1)
    appendAudit(collection, id, '删除', '记录已从当前版本移除')
    persist()
  }

  const updateBoundary = (boundary: ThreatModelState['boundary']): void => {
    data.value.boundary = boundary
    appendAudit('boundary', boundary.id, '更新', `${boundary.name} 的系统边界已更新`)
    persist()
  }

  const saveThreat = (threat: Threat): void => {
    saveEntity('threats', threat)
  }

  const createVersion = (
    label: string,
    notes: string,
    affectedThreatIds: string[],
  ): VersionSnapshot => {
    const revision = data.value.currentRevision + 1
    const snapshot: VersionSnapshot = {
      id: createId('ver'),
      revision,
      label,
      createdAt: new Date().toISOString(),
      author: '当前用户',
      notes,
      threatIds: data.value.threats.map((threat) => threat.id),
      componentIds: data.value.components.map((component) => component.id),
      flowIds: data.value.flows.map((flow) => flow.id),
      controlIds: data.value.controls.map((control) => control.id),
      riskIds: data.value.risks.map((risk) => risk.id),
      affectedThreatIds,
    }
    data.value.currentRevision = revision
    data.value.versions.unshift(snapshot)
    // 只有受影响威胁提升修订号并重新会签；其余威胁结论继续保留。
    const affected = new Set(affectedThreatIds)
    data.value.threats = data.value.threats.map((threat) =>
      affected.has(threat.id)
        ? { ...threat, revision, reviewStatus: 'in_review' as const }
        : threat,
    )
    reconcileReviewStatuses()
    appendAudit(
      'version',
      snapshot.id,
      '创建版本',
      `${label} 已创建，${affectedThreatIds.length} 条威胁进入重新审核，其余会签结论继续保留`,
    )
    persist()
    return snapshot
  }

  const submitDecision = (
    threatId: string,
    role: ActorRole,
    decision: DecisionType,
    actor: string,
    comment: string,
  ): void => {
    const threat = data.value.threats.find((item) => item.id === threatId)
    if (!threat) return
    data.value.decisions = data.value.decisions.filter(
      (item) => !(item.threatId === threatId && item.role === role && item.revision === threat.revision),
    )
    data.value.decisions.unshift({
      id: createId('dec'),
      threatId,
      role,
      actor,
      decision,
      comment,
      createdAt: new Date().toISOString(),
      revision: threat.revision,
    })

    // 会签是否有效由统一核对给出：证据过期、接受过期、缓解冲突时即使三方都点了通过也不能通过。
    const evaluation = evaluateCountersign(data.value, threat)
    threat.reviewStatus = evaluation.outcome

    const decisionLabel: Record<DecisionType, string> = {
      accept: '接受',
      degrade: '降级',
      evidence_required: '要求补证',
      approved: '会签通过',
      rejected: '驳回',
    }
    appendAudit(
      'threat',
      threatId,
      decisionLabel[decision],
      `${actor}（${role}）提交会签意见`,
    )
    persist()
  }

  const updateMitigationStatus = (
    taskId: string,
    status: ThreatModelState['mitigations'][number]['status'],
  ): void => {
    const task = data.value.mitigations.find((item) => item.id === taskId)
    if (!task) return
    task.status = status
    appendAudit('mitigation', task.id, '更新状态', `${task.title} 更新为 ${status}`)
    persist()
  }

  const acceptRisk = (riskId: string, expiresAt: string, condition: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'accepted'
    risk.acceptanceExpiresAt = expiresAt
    risk.acceptanceCondition = condition
    appendAudit('risk', risk.id, '接受风险', `接受有效至 ${expiresAt}：${condition}`)
    persist()
  }

  const closeRisk = (riskId: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'closed'
    appendAudit('risk', risk.id, '关闭风险', '风险已关闭并从开放风险中移除')
    persist()
  }

  const resetDemo = (): void => {
    data.value = resetState()
    reconcileReviewStatuses()
    lastSavedAt.value = new Date().toISOString()
  }

  const exportReport = (): string => {
    const blockedCount = data.value.threats.filter((threat) => {
      const outcome = evaluationFor(threat.id)?.outcome
      return threat.reviewStatus !== 'draft' && outcome && outcome !== 'approved'
    }).length
    const lines = [
      `# ${data.value.boundary.name} 威胁建模报告`,
      '',
      `生成时间：${new Date().toISOString()}`,
      `当前版本：v1.${data.value.currentRevision}`,
      `建模范围：${data.value.boundary.inScope}`,
      `排除范围：${data.value.boundary.outOfScope}`,
      '',
      '## 风险摘要',
      `- 资产与组件：${data.value.components.length}`,
      `- 威胁：${data.value.threats.length}`,
      `- 开放关键威胁：${metrics.value.critical}`,
      `- 威胁覆盖率：${metrics.value.coverage}%`,
      `- 待处理校验问题：${issues.value.length}`,
      `- 会签核对未通过威胁：${blockedCount}（含阻塞、审核中、驳回，均不得计作已完成会签）`,
      '',
      '## 威胁清单',
      ...data.value.threats.map((threat) => {
        const evaluation = evaluationFor(threat.id)
        const conclusion = evaluation
          ? countersignOutcomeLabel(evaluation.outcome)
          : threat.reviewStatus
        return `- ${threat.code} [${threat.severity}/${conclusion}@v1.${threat.revision}] ${threat.title}：${threat.description}`
      }),
      '',
      '## 会签有效性核对',
      '> 同一次判断覆盖三方意见、证据有效期、风险接受期限与缓解冲突；存在阻塞时不得得出通过结论。',
      ...data.value.threats.flatMap((threat) => {
        const evaluation = evaluationFor(threat.id)
        if (!evaluation || threat.reviewStatus === 'draft') return []
        const header = `### ${threat.code} ${threat.title}（v1.${threat.revision}）：${countersignOutcomeLabel(evaluation.outcome)}`
        if (evaluation.outcome === 'approved') {
          return [
            header,
            `- 三方意见：${evaluation.roleStates
              .map((state) => (state ? `${state.actor}/${state.decision}` : '缺签'))
              .join('、')}`,
            '- 证据有效期、风险接受期限、缓解冲突：全部通过',
            '',
          ]
        }
        return [
          header,
          ...evaluation.blockers.map(
            (blocker) =>
              `- [${blocker.severity}] ${blocker.title}｜条目：${blocker.subject}｜当前值：${blocker.currentValue}｜待补动作：${blocker.requiredAction}`,
          ),
          '',
        ]
      }),
      '## 风险接受',
      ...data.value.risks
        .filter((risk) => risk.status === 'accepted')
        .map((risk) => {
          const expired = isExpired(risk.acceptanceExpiresAt)
          return `- ${risk.code} ${risk.title}，有效至 ${risk.acceptanceExpiresAt ?? '未设置'}${expired ? '（已过期，会签核对阻塞）' : ''}，条件：${risk.acceptanceCondition ?? '未填写'}`
        }),
      '',
      '## 校验问题',
      ...issues.value.map((issue) => `- [${issue.severity}] ${issue.title}：${issue.detail}`),
      '',
      '## 会签记录（历史可查）',
      ...data.value.decisions
        .slice()
        .sort((a, b) => a.revision - b.revision || a.createdAt.localeCompare(b.createdAt))
        .map(
          (decision) =>
            `- v1.${decision.revision} ${decision.createdAt} ${decision.actor}（${decision.role}）${decision.decision}：${decision.comment}`,
        ),
    ]
    return lines.join('\n')
  }

  return {
    data,
    lastSavedAt,
    metrics,
    issues,
    countersigns,
    pendingReviews,
    saveEntity,
    removeEntity,
    updateBoundary,
    saveThreat,
    createVersion,
    submitDecision,
    updateMitigationStatus,
    acceptRisk,
    closeRisk,
    resetDemo,
    exportReport,
    reviewProgress,
    decisionsForThreat,
    evaluationFor,
    countersignOutcomeLabel,
  }
})
