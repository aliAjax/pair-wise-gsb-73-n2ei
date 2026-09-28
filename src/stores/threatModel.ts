import { computed, ref } from 'vue'
import { defineStore } from 'pinia'
import type {
  ActorRole,
  AuditEvent,
  DecisionType,
  Threat,
  ThreatModelState,
  VersionSnapshot,
} from '@/models/domain'
import { createId, loadState, resetState, saveState } from '@/services/repository'
import {
  assessAllCountersigns,
  assessCountersign,
  dashboardMetrics,
  getValidationIssues,
  isExpired,
  reviewProgress,
} from '@/services/selectors'

const REVIEW_STATUS_LABELS: Record<string, string> = {
  draft: '草稿',
  in_review: '审核中（存在阻塞）',
  approved: '会签通过',
  rejected: '已驳回',
}

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
  const countersignAssessments = computed(() => assessAllCountersigns(data.value))
  const countersignMap = computed(() => {
    const map = new Map(countersignAssessments.value.map((item) => [item.threatId, item]))
    return map
  })
  const pendingReviews = computed(() =>
    data.value.threats.filter(
      (threat) => countersignMap.value.get(threat.id)?.reviewStatus !== 'approved',
    ),
  )

  const assessmentFor = (threatId: string) => countersignMap.value.get(threatId)

  const persist = (): void => {
    saveState(data.value)
    lastSavedAt.value = new Date().toISOString()
  }

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

  /**
   * 按当前模型状态重新核对每条威胁的会签有效性，并把持久化的 reviewStatus
   * 与核对结论对齐。历史会签意见不会被改动或删除；只在结论发生变化时记录审计。
   * 在任何会签依据（意见、证据、风险接受、缓解任务、版本）变更后调用。
   */
  const reconcileCountersigns = (): void => {
    countersignAssessments.value.forEach((assessment) => {
      const threat = data.value.threats.find((item) => item.id === assessment.threatId)
      if (!threat || threat.reviewStatus === assessment.reviewStatus) return
      const previous = threat.reviewStatus
      threat.reviewStatus = assessment.reviewStatus
      if (assessment.effective) {
        appendAudit(
          'threat',
          threat.id,
          '会签核对通过',
          `${threat.code} 三方意见、证据有效期、风险接受与缓解冲突核对全部通过，结论由“${REVIEW_STATUS_LABELS[previous] ?? previous}”恢复为会签通过。`,
        )
      } else if (assessment.reviewStatus === 'rejected') {
        appendAudit(
          'threat',
          threat.id,
          '会签被驳回',
          `${threat.code} 存在驳回意见，会签结论由“${REVIEW_STATUS_LABELS[previous] ?? previous}”调整为已驳回。`,
        )
      } else {
        const summary = assessment.blockers
          .slice(0, 3)
          .map((blocker) => blocker.title)
          .join('；')
        const suffix = assessment.blockers.length > 3 ? ` 等 ${assessment.blockers.length} 项阻塞` : ''
        appendAudit(
          'threat',
          threat.id,
          '会签核对阻塞',
          `${threat.code} 原会签结论不再成立（${REVIEW_STATUS_LABELS[previous] ?? previous}）：${summary}${suffix}，已暂停通过结论。`,
        )
      }
    })
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
    if (['evidence', 'controls', 'mitigations'].includes(collection)) {
      reconcileCountersigns()
    }
    persist()
  }

  const removeEntity = (collection: CollectionKey, id: string): void => {
    const target = data.value[collection] as unknown as IdentifiedEntity[]
    const index = target.findIndex((entry) => entry.id === id)
    if (index < 0) return
    target.splice(index, 1)
    appendAudit(collection, id, '删除', '记录已从当前版本移除')
    if (['evidence', 'controls', 'mitigations'].includes(collection)) {
      reconcileCountersigns()
    }
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
    // 只有受影响威胁进入新版本重新会签；其余威胁保持原 revision 与既有结论，
    // 其旧 revision 上的历史会签意见因此仍可查询。
    data.value.threats = data.value.threats.map((threat) => {
      if (!affectedThreatIds.includes(threat.id)) {
        return threat
      }
      return { ...threat, revision, reviewStatus: 'in_review' }
    })
    appendAudit(
      'version',
      snapshot.id,
      '创建版本',
      `${label} 已创建，${affectedThreatIds.length} 条威胁进入重新审核，其余会签结论保留。`,
    )
    reconcileCountersigns()
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

    const assessment = assessCountersign(data.value, threat)
    threat.reviewStatus = assessment.reviewStatus

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
      `${actor}（${role}）提交会签意见；核对结论：${
        assessment.effective
          ? '会签通过'
          : assessment.reviewStatus === 'rejected'
            ? '已驳回'
            : `存在 ${assessment.blockers.length} 项阻塞，不能通过`
      }`,
    )
    reconcileCountersigns()
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
    reconcileCountersigns()
    persist()
  }

  const acceptRisk = (riskId: string, expiresAt: string, condition: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'accepted'
    risk.acceptanceExpiresAt = expiresAt
    risk.acceptanceCondition = condition
    appendAudit('risk', risk.id, '接受风险', `接受有效至 ${expiresAt}：${condition}`)
    reconcileCountersigns()
    persist()
  }

  const closeRisk = (riskId: string): void => {
    const risk = data.value.risks.find((item) => item.id === riskId)
    if (!risk) return
    risk.status = 'closed'
    appendAudit('risk', risk.id, '关闭风险', '风险已关闭并从开放风险中移除')
    reconcileCountersigns()
    persist()
  }

  const resetDemo = (): void => {
    data.value = resetState()
    reconcileCountersigns()
    persist()
    lastSavedAt.value = new Date().toISOString()
  }

  // 首次加载时按当前证据/风险接受/缓解状态对持久化的会签结论做一次对账，
  // 防止页面与报告继续展示历史遗留的“假通过”。
  reconcileCountersigns()
  persist()

  const exportReport = (): string => {
    const assessments = assessAllCountersigns(data.value)
    const effectiveCount = assessments.filter((item) => item.effective).length
    const blocked = assessments.filter((item) => !item.effective)
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
      '',
      '## 会签有效性核对',
      `- 有效会签：${effectiveCount}/${data.value.threats.length}（三方意见、证据有效期、风险接受期限、缓解冲突同次核对）`,
      `- 不能通过：${blocked.length} 条`,
      ...(blocked.length === 0
        ? ['- 全部威胁核对通过，无阻塞项。']
        : blocked.flatMap((assessment) => {
            const threat = data.value.threats.find((item) => item.id === assessment.threatId)
            const header = [
              `- 【阻塞】${threat?.code ?? assessment.threatId} ${threat?.title ?? ''}（v1.${assessment.revision}，结论：${
                assessment.reviewStatus === 'rejected' ? '已驳回' : '暂停通过'
              }，${assessment.blockers.length} 项）`,
            ]
            return header.concat(
              assessment.blockers.map(
                (blocker) =>
                  `  - [${blocker.label}] ${blocker.title}｜${blocker.currentValue}｜待补动作：${blocker.remediation}`,
              ),
            )
          })),
      '',
      '## 威胁清单',
      ...data.value.threats.map((threat) => {
        const effective = assessments.find((item) => item.threatId === threat.id)?.effective
        return `- ${threat.code} [${threat.severity}/${threat.reviewStatus}${effective ? '' : '/会签失效'}] ${threat.title}：${threat.description}`
      }),
      '',
      '## 风险接受',
      ...data.value.risks
        .filter((risk) => risk.status === 'accepted')
        .map((risk) => {
          const expired = isExpired(risk.acceptanceExpiresAt)
          return `- ${risk.code} ${risk.title}，有效至 ${risk.acceptanceExpiresAt ?? '未设置'}${expired ? '（已过期，会签阻塞）' : ''}，条件：${risk.acceptanceCondition ?? '未填写'}`
        }),
      '',
      '## 校验问题',
      ...issues.value.map((issue) => `- [${issue.severity}] ${issue.title}：${issue.detail}`),
      '',
      '## 会签记录（含历史版本）',
      ...data.value.decisions
        .slice()
        .sort((a, b) => (a.revision === b.revision ? 0 : a.revision < b.revision ? 1 : -1))
        .map(
          (decision) =>
            `- [v1.${decision.revision}] ${decision.createdAt} ${decision.actor}（${decision.role}）${decision.decision}：${decision.comment}`,
        ),
    ]
    return lines.join('\n')
  }

  return {
    data,
    lastSavedAt,
    metrics,
    issues,
    pendingReviews,
    countersignAssessments,
    assessmentFor,
    reconcileCountersigns,
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
  }
})
