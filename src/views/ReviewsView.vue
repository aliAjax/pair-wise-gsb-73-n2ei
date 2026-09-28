<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import ProgressBar from 'primevue/progressbar'
import Select from 'primevue/select'
import Tag from 'primevue/tag'
import Textarea from 'primevue/textarea'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import type { ActorRole, DecisionType, ReviewDecision, Threat } from '@/models/domain'
import {
  decisionsForThreat,
  decisionLabel as decisionText,
  reviewProgress,
} from '@/services/selectors'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const selectedThreatId = ref('')
const decisionVisible = ref(false)
const scopeAll = ref(false)

const roleOptions: { label: string; value: ActorRole; actor: string }[] = [
  { label: '开发负责人', value: 'development', actor: '赵恺' },
  { label: '安全负责人', value: 'security', actor: '王岚' },
  { label: '业务负责人', value: 'business', actor: '宋雨' },
]
const decisionOptions = [
  { label: '通过', value: 'approved' },
  { label: '接受条件', value: 'accept' },
  { label: '同意降级', value: 'degrade' },
  { label: '要求补证', value: 'evidence_required' },
  { label: '驳回', value: 'rejected' },
]

const form = reactive<{
  role: ActorRole
  decision: DecisionType
  actor: string
  comment: string
}>({
  role: 'security',
  decision: 'approved',
  actor: '王岚',
  comment: '',
})

const latestVersion = computed(() => store.data.versions[0])
const affectedIds = computed(
  () => new Set(latestVersion.value?.affectedThreatIds ?? store.data.threats.map((threat) => threat.id)),
)
const reviewThreats = computed(() =>
  scopeAll.value
    ? store.data.threats
    : store.data.threats.filter((threat) => affectedIds.value.has(threat.id)),
)
const retainedThreats = computed(() =>
  store.data.threats.filter((threat) => !affectedIds.value.has(threat.id)),
)
const selectedThreat = computed(
  () => store.data.threats.find((threat) => threat.id === selectedThreatId.value) ?? null,
)
const selectedAssessment = computed(() =>
  selectedThreat.value ? store.assessmentFor(selectedThreat.value.id) : undefined,
)

interface RevisionGroup {
  revision: number
  decisions: ReviewDecision[]
}

const decisionHistory = computed<RevisionGroup[]>(() => {
  if (!selectedThreat.value) return []
  const groups = new Map<number, ReviewDecision[]>()
  store.data.decisions
    .filter((decision) => decision.threatId === selectedThreat.value?.id)
    .forEach((decision) => {
      const list = groups.get(decision.revision) ?? []
      list.push(decision)
      groups.set(decision.revision, list)
    })
  return [...groups.entries()]
    .map(([revision, decisions]) => ({ revision, decisions }))
    .sort((a, b) => b.revision - a.revision)
})

const isAffected = (threat: Threat): boolean => affectedIds.value.has(threat.id)

const statusForRole = (threat: Threat, role: ActorRole): DecisionType | 'pending' =>
  decisionsForThreat(store.data.decisions, threat.id, threat.revision).find(
    (decision) => decision.role === role,
  )?.decision ?? 'pending'

const statusTextForRole = (threat: Threat, role: ActorRole): string => {
  const status = statusForRole(threat, role)
  return status === 'pending' ? '待提交' : decisionText(status)
}

const openDecision = (): void => {
  if (!selectedThreat.value) return
  form.comment = ''
  form.role = 'security'
  form.actor = '王岚'
  form.decision = 'approved'
  decisionVisible.value = true
}

const changeRole = (): void => {
  form.actor = roleOptions.find((item) => item.value === form.role)?.actor ?? form.actor
}

const submitDecision = (): void => {
  if (!selectedThreat.value) return
  if (!form.comment.trim()) {
    toast.add({ severity: 'error', summary: '校验失败', detail: '会签意见不能为空', life: 3000 })
    return
  }
  store.submitDecision(
    selectedThreat.value.id,
    form.role,
    form.decision,
    form.actor,
    form.comment,
  )
  decisionVisible.value = false
  const assessment = store.assessmentFor(selectedThreat.value.id)
  toast.add({
    severity: assessment?.effective
      ? 'success'
      : assessment?.reviewStatus === 'rejected'
        ? 'error'
        : 'warn',
    summary: assessment?.effective ? '会签核对通过' : '会签核对未通过',
    detail: assessment
      ? assessment.effective
        ? '三方意见与有效期、冲突核对全部通过'
        : assessment.reviewStatus === 'rejected'
          ? '存在驳回意见'
          : `仍有 ${assessment.blockers.length} 项阻塞，不能得到通过结论`
      : '审核状态已重新计算',
    life: 3200,
  })
}
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="受影响范围"
      title="逐项会签中心"
      :description="`三方意见、证据有效期、风险接受期限与缓解冲突在同一次核对中判断；当前版本 ${latestVersion?.label ?? '未建立'} 仅受影响威胁需要重新会签。`"
    />

    <section class="version-context">
      <div>
        <span>审核基线</span>
        <strong>{{ latestVersion?.label ?? '尚未建立版本' }}</strong>
      </div>
      <div>
        <span>受影响威胁</span>
        <strong>{{ affectedIds.size }} 条 · 列表展示 {{ reviewThreats.length }} 条</strong>
      </div>
      <div>
        <span>有效会签（全模型）</span>
        <strong>{{ store.countersignAssessments.filter((item) => item.effective).length }}/{{ store.data.threats.length }}</strong>
      </div>
    </section>

    <div v-if="retainedThreats.length > 0 && !scopeAll" class="retain-banner">
      <i class="pi pi-lock"></i>
      <div>
        <strong>{{ retainedThreats.length }} 条未受影响威胁保留原会签结论</strong>
        <span>
          {{ retainedThreats.map((threat) => threat.code).join('、') }}
          未进入本版本重新会签；若其证据过期或风险接受到期，仍会在核对中被标记为阻塞。
        </span>
      </div>
      <Button label="查看全部威胁与历史会签" text size="small" @click="scopeAll = true" />
    </div>

    <div class="scope-switch">
      <Button
        :label="scopeAll ? '仅受影响威胁' : '查看全部威胁'"
        :icon="scopeAll ? 'pi pi-filter' : 'pi pi-list'"
        severity="secondary"
        outlined
        size="small"
        @click="scopeAll = !scopeAll"
      />
    </div>

    <div class="review-board">
      <section class="review-list">
        <article
          v-for="threat in reviewThreats"
          :key="threat.id"
          class="review-card"
          :class="{ selected: selectedThreatId === threat.id }"
          @click="selectedThreatId = threat.id"
        >
          <div class="review-card-head">
            <div>
              <span class="mono">{{ threat.code }}</span>
              <h2>{{ threat.title }}</h2>
              <small v-if="!isAffected(threat)" class="retained-mark">本版本未受影响 · 结论保留（v1.{{ threat.revision }}）</small>
            </div>
            <StatusTag :value="store.assessmentFor(threat.id)?.reviewStatus ?? threat.reviewStatus" kind="review" />
          </div>
          <div class="role-grid">
            <div v-for="role in roleOptions" :key="role.value" class="role-state">
              <span>{{ role.label }}</span>
              <strong :class="{ pending: statusForRole(threat, role.value) === 'pending' }">
                {{ statusTextForRole(threat, role.value) }}
              </strong>
            </div>
          </div>
          <ProgressBar
            :value="reviewProgress(decisionsForThreat(store.data.decisions, threat.id, threat.revision))"
            :show-value="false"
            class="review-progress"
          />
          <div
            v-if="store.assessmentFor(threat.id) && !store.assessmentFor(threat.id)!.effective"
            class="card-blocker-hint"
          >
            <i class="pi pi-exclamation-triangle"></i>
            {{ store.assessmentFor(threat.id)!.blockers.length }} 项阻塞，会签不能通过
          </div>
        </article>
      </section>

      <aside class="decision-panel">
        <template v-if="selectedThreat">
          <div class="decision-head">
            <div>
              <span class="mono">{{ selectedThreat.code }}</span>
              <h2>{{ selectedThreat.title }}</h2>
            </div>
            <StatusTag :value="selectedAssessment?.reviewStatus ?? selectedThreat.reviewStatus" kind="review" />
          </div>
          <p class="decision-description">{{ selectedThreat.description }}</p>

          <section class="validity-section">
            <div class="validity-title">
              <h3>会签有效性核对</h3>
              <Tag
                v-if="selectedAssessment?.effective"
                value="核对通过"
                severity="success"
              />
              <Tag v-else value="存在阻塞 · 不能通过" severity="danger" />
            </div>
            <p class="validity-note">
              基于 v1.{{ selectedThreat.revision }} 的三方意见，与当前证据有效期、风险接受期限、缓解冲突同次判断。
            </p>

            <div v-if="selectedAssessment && selectedAssessment.blockers.length > 0" class="blocker-list">
              <article v-for="blocker in selectedAssessment.blockers" :key="blocker.id" class="blocker-item">
                <div class="blocker-head">
                  <span class="blocker-label">{{ blocker.label }}</span>
                  <strong>{{ blocker.title }}</strong>
                </div>
                <div class="blocker-row">
                  <span>当前值</span>
                  <p>{{ blocker.currentValue }}</p>
                </div>
                <div class="blocker-row">
                  <span>情况说明</span>
                  <p>{{ blocker.detail }}</p>
                </div>
                <div class="blocker-row action">
                  <span>待补动作</span>
                  <p>{{ blocker.remediation }}</p>
                </div>
              </article>
            </div>
            <div v-else class="validity-ok">
              <i class="pi pi-check-circle"></i>
              三方均已通过，控制证据在有效期内，风险接受未到期，且不存在互斥缓解措施。
            </div>
          </section>

          <Button
            label="提交会签意见"
            icon="pi pi-pencil"
            :disabled="!isAffected(selectedThreat)"
            class="submit-button"
            @click="openDecision"
          />
          <small v-if="!isAffected(selectedThreat)" class="muted disabled-note">
            该威胁未列入本版本受影响范围，无需重新会签；历史意见见下方。
          </small>

          <section class="decision-history">
            <h3>会签记录（按版本，历史可追溯）</h3>
            <div v-for="group in decisionHistory" :key="group.revision" class="history-group">
              <div class="history-revision">
                <span>v1.{{ group.revision }}</span>
                <small v-if="group.revision === selectedThreat.revision">当前核对基线</small>
                <small v-else>历史版本（只读）</small>
              </div>
              <article v-for="decision in group.decisions" :key="decision.id" class="decision-entry">
                <div>
                  <strong>{{ decision.actor }}</strong>
                  <span>{{ roleOptions.find((role) => role.value === decision.role)?.label }}</span>
                </div>
                <StatusTag :value="decision.decision" kind="review" />
                <p>{{ decision.comment }}</p>
                <time>{{ new Date(decision.createdAt).toLocaleString('zh-CN') }}</time>
              </article>
            </div>
            <div v-if="decisionHistory.length === 0" class="empty-state">尚未提交会签意见。</div>
          </section>
        </template>
        <div v-else class="empty-state">从左侧选择一条威胁查看会签核对结果。</div>
      </aside>
    </div>

    <Dialog v-model:visible="decisionVisible" header="提交会签意见" modal :style="{ width: '620px' }">
      <div class="editor-form">
        <div class="field">
          <label>会签角色</label>
          <Select
            v-model="form.role"
            :options="roleOptions"
            option-label="label"
            option-value="value"
            @change="changeRole"
          />
        </div>
        <div class="field">
          <label>会签人</label>
          <InputText v-model="form.actor" />
        </div>
        <div class="field field-wide">
          <label>意见类型</label>
          <Select
            v-model="form.decision"
            :options="decisionOptions"
            option-label="label"
            option-value="value"
          />
        </div>
        <div class="field field-wide">
          <label>意见与条件</label>
          <Textarea
            v-model="form.comment"
            rows="5"
            placeholder="通过、降级、接受或补证都需要写明具体条件"
          />
        </div>
      </div>
      <template #footer>
        <Button label="取消" severity="secondary" outlined @click="decisionVisible = false" />
        <Button label="提交意见" icon="pi pi-check" @click="submitDecision" />
      </template>
    </Dialog>
  </div>
</template>

<style scoped>
.version-context {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 1px;
  overflow: hidden;
  border: 1px solid #dfe4eb;
  border-radius: 6px;
  background: #dfe4eb;
}

.version-context > div {
  display: grid;
  gap: 7px;
  padding: 14px 16px;
  background: #fff;
}

.version-context span {
  color: #717c8f;
  font-size: 11px;
}

.retain-banner {
  display: flex;
  align-items: center;
  gap: 13px;
  margin-top: 14px;
  padding: 12px 16px;
  border: 1px solid #cdd8e6;
  border-left: 4px solid #4c78a8;
  border-radius: 6px;
  background: #f5f8fc;
}

.retain-banner > i {
  color: #4c78a8;
  font-size: 16px;
}

.retain-banner > div {
  display: grid;
  gap: 3px;
  flex: 1;
}

.retain-banner span {
  color: #5d6a80;
  font-size: 12px;
}

.scope-switch {
  margin: 14px 0 4px;
}

.review-board {
  display: grid;
  grid-template-columns: minmax(0, 1.25fr) minmax(420px, 0.75fr);
  gap: 16px;
  align-items: start;
}

.review-list {
  display: grid;
  gap: 12px;
}

.review-card {
  padding: 16px;
  border: 1px solid #dde2ea;
  border-radius: 7px;
  background: #fff;
  cursor: pointer;
}

.review-card:hover,
.review-card.selected {
  border-color: #7898bb;
  box-shadow: 0 0 0 1px rgba(70, 108, 150, 0.1);
}

.review-card-head,
.decision-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 18px;
}

.review-card h2,
.decision-head h2 {
  margin: 6px 0 0;
  font-size: 16px;
}

.retained-mark {
  display: inline-block;
  margin-top: 6px;
  color: #4c78a8;
  font-size: 11px;
}

.role-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  margin-top: 16px;
}

.role-state {
  display: grid;
  gap: 4px;
  padding: 9px 10px;
  border: 1px solid #e2e6ec;
  border-radius: 5px;
  background: #f9fafb;
}

.role-state span {
  color: #737e91;
  font-size: 10px;
}

.role-state strong {
  color: #2e684f;
  font-size: 11px;
}

.role-state strong.pending {
  color: #a05a00;
}

.review-progress {
  height: 4px;
  margin-top: 14px;
}

.card-blocker-hint {
  display: flex;
  align-items: center;
  gap: 7px;
  margin-top: 10px;
  padding: 7px 10px;
  border-radius: 5px;
  color: #a3402f;
  background: #fdf1ee;
  font-size: 11px;
  font-weight: 600;
}

.decision-panel {
  position: sticky;
  top: 82px;
  max-height: calc(100vh - 106px);
  padding: 18px;
  overflow: auto;
  border: 1px solid #dde2ea;
  border-radius: 7px;
  background: #fff;
}

.decision-description {
  margin: 14px 0 18px;
  color: #59657a;
  font-size: 13px;
  line-height: 1.65;
}

.validity-section {
  border: 1px solid #e3e7ee;
  border-radius: 7px;
  padding: 14px;
  background: #fafbfd;
}

.validity-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.validity-title h3 {
  margin: 0;
  font-size: 13px;
}

.validity-note {
  margin: 7px 0 12px;
  color: #7b8698;
  font-size: 11px;
  line-height: 1.5;
}

.blocker-list {
  display: grid;
  gap: 10px;
}

.blocker-item {
  padding: 11px 12px;
  border: 1px solid #f0cfc7;
  border-left: 3px solid #c64b39;
  border-radius: 5px;
  background: #fff;
}

.blocker-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.blocker-label {
  padding: 2px 7px;
  border-radius: 10px;
  color: #fff;
  background: #c64b39;
  font-size: 10px;
  white-space: nowrap;
}

.blocker-head strong {
  font-size: 12px;
}

.blocker-row {
  display: grid;
  grid-template-columns: 56px minmax(0, 1fr);
  gap: 8px;
  margin-top: 5px;
}

.blocker-row span {
  color: #8a93a3;
  font-size: 10px;
}

.blocker-row p {
  margin: 0;
  color: #4f5a6d;
  font-size: 11px;
  line-height: 1.55;
}

.blocker-row.action p {
  color: #9a3f2d;
  font-weight: 600;
}

.validity-ok {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 10px 12px;
  border-radius: 5px;
  color: #2e684f;
  background: #eef8f2;
  font-size: 12px;
  line-height: 1.5;
}

.submit-button {
  margin-top: 14px;
  width: 100%;
}

.disabled-note {
  display: block;
  margin-top: 6px;
  text-align: center;
}

.decision-history {
  margin-top: 22px;
  padding-top: 18px;
  border-top: 1px solid #e5e9ef;
}

.decision-history h3 {
  margin: 0 0 12px;
  font-size: 13px;
}

.history-group + .history-group {
  margin-top: 14px;
}

.history-revision {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}

.history-revision span {
  font-size: 11px;
  font-weight: 700;
  color: #3268a6;
}

.history-revision small {
  color: #8a93a3;
  font-size: 10px;
}

.decision-entry {
  position: relative;
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 8px;
  padding: 11px 0;
  border-bottom: 1px solid #eef0f3;
}

.decision-entry > div {
  display: grid;
  gap: 3px;
}

.decision-entry span,
.decision-entry time {
  color: #7a8496;
  font-size: 10px;
}

.decision-entry p {
  grid-column: 1 / -1;
  margin: 0;
  color: #566176;
  font-size: 12px;
  line-height: 1.5;
}

.muted {
  color: #8a93a3;
}
</style>
