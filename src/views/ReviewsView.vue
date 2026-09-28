<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Button from 'primevue/button'
import Dialog from 'primevue/dialog'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import ProgressBar from 'primevue/progressbar'
import Select from 'primevue/select'
import Textarea from 'primevue/textarea'
import { useToast } from 'primevue/usetoast'
import PageHeader from '@/components/PageHeader.vue'
import StatusTag from '@/components/StatusTag.vue'
import type {
  ActorRole,
  CountersignBlocker,
  DecisionType,
  RoleDecisionState,
  Threat,
} from '@/models/domain'
import { decisionsForThreat, reviewProgress } from '@/services/selectors'
import { useThreatModelStore } from '@/stores/threatModel'

const store = useThreatModelStore()
const toast = useToast()
const selectedThreatId = ref(
  store.data.versions[0]?.affectedThreatIds[0] ?? store.data.threats[0]?.id ?? '',
)
const decisionVisible = ref(false)

const roleOptions: { label: string; value: ActorRole; actor: string }[] = [
  { label: '开发负责人', value: 'development', actor: '赵恺' },
  { label: '安全负责人', value: 'security', actor: '王岚' },
  { label: '业务负责人', value: 'business', actor: '宋雨' },
]
const decisionOptions: { label: string; value: DecisionType }[] = [
  { label: '通过', value: 'approved' },
  { label: '接受条件', value: 'accept' },
  { label: '同意降级', value: 'degrade' },
  { label: '要求补证', value: 'evidence_required' },
  { label: '驳回', value: 'rejected' },
]

const categoryLabels: Record<CountersignBlocker['category'], string> = {
  opinion: '三方意见',
  evidence: '控制证据有效期',
  acceptance: '风险接受期限',
  conflict: '缓解冲突',
}

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
const affectedThreats = computed(() =>
  store.data.threats.filter((threat) => affectedIds.value.has(threat.id)),
)
// 未进入本次版本重审的威胁：会签结论继续保留，并按当前证据/接受期限实时核对。
const retainedThreats = computed(() =>
  store.data.threats.filter((threat) => !affectedIds.value.has(threat.id)),
)

const selectedThreat = computed(
  () => store.data.threats.find((threat) => threat.id === selectedThreatId.value) ?? null,
)
const selectedEvaluation = computed(() =>
  selectedThreat.value ? store.evaluationFor(selectedThreat.value.id) : undefined,
)
const currentDecisions = computed(() =>
  selectedThreat.value
    ? decisionsForThreat(
        store.data.decisions,
        selectedThreat.value.id,
        selectedThreat.value.revision,
      )
    : [],
)

// 历史会签：按修订分组（当前修订除外），版本升级后旧意见仍可逐条查询。
const historicalGroups = computed(() => {
  if (!selectedThreat.value) return []
  const currentRevision = selectedThreat.value.revision
  const revisions = [
    ...new Set(
      store.data.decisions
        .filter(
          (decision) =>
            decision.threatId === selectedThreat.value?.id && decision.revision !== currentRevision,
        )
        .map((decision) => decision.revision),
    ),
  ].sort((a, b) => b - a)
  return revisions.map((revision) => ({
    revision,
    decisions: store.data.decisions
      .filter((decision) => decision.threatId === selectedThreat.value?.id && decision.revision === revision)
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt)),
  }))
})

const evaluationOf = (threat: Threat) => store.evaluationFor(threat.id)

const roleStateOf = (threat: Threat, role: ActorRole): RoleDecisionState | null =>
  evaluationOf(threat)?.roleStates[roleOptions.findIndex((item) => item.value === role)] ?? null

const progressOf = (threat: Threat): number =>
  reviewProgress(decisionsForThreat(store.data.decisions, threat.id, threat.revision))

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
  const evaluation = store.evaluationFor(selectedThreat.value.id)
  if (evaluation?.outcome === 'approved') {
    toast.add({ severity: 'success', summary: '会签核对通过', detail: '三方意见与有效期核对全部满足', life: 2800 })
  } else if (evaluation?.outcome === 'rejected') {
    toast.add({ severity: 'warn', summary: '会签已驳回', detail: '结论：会签驳回', life: 2800 })
  } else {
    toast.add({
      severity: 'warn',
      summary: '意见已记录，但会签未通过',
      detail: `当前结论：${store.countersignOutcomeLabel(evaluation?.outcome ?? 'in_review')}，请按阻塞清单补齐`,
      life: 3600,
    })
  }
}

const decisionLabel = (decision: DecisionType | 'pending'): string =>
  decision === 'pending'
    ? '待提交'
    : decisionOptions.find((item) => item.value === decision)?.label ?? decision

const isAffected = (threat: Threat): boolean => affectedIds.value.has(threat.id)
</script>

<template>
  <div class="page">
    <PageHeader
      eyebrow="受影响范围"
      title="逐项会签中心"
      :description="`当前版本 ${latestVersion?.label ?? '未建立'} 仅受变更影响的威胁重新会签；其余威胁结论保留，并持续核对证据与风险接受期限。`"
    />

    <section class="version-context">
      <div>
        <span>审核基线</span>
        <strong>{{ latestVersion?.label ?? '尚未建立版本' }}</strong>
      </div>
      <div>
        <span>受影响威胁</span>
        <strong>{{ affectedThreats.length }} 条</strong>
      </div>
      <div>
        <span>保留结论</span>
        <strong>{{ retainedThreats.length }} 条</strong>
      </div>
    </section>

    <div class="review-board">
      <section class="review-list">
        <h3 class="list-heading">本版本重新会签（{{ affectedThreats.length }}）</h3>
        <article
          v-for="threat in affectedThreats"
          :key="threat.id"
          class="review-card"
          :class="{ selected: selectedThreatId === threat.id }"
          @click="selectedThreatId = threat.id"
        >
          <div class="review-card-head">
            <div>
              <span class="mono">{{ threat.code }}</span>
              <h2>{{ threat.title }}</h2>
            </div>
            <StatusTag :value="evaluationOf(threat)?.outcome ?? threat.reviewStatus" kind="review" />
          </div>
          <div class="role-grid">
            <div v-for="role in roleOptions" :key="role.value" class="role-state">
              <span>{{ role.label }}</span>
              <strong :class="{ pending: !roleStateOf(threat, role.value) }">
                {{ roleStateOf(threat, role.value) ? decisionLabel(roleStateOf(threat, role.value)!.decision) : '待提交' }}
              </strong>
            </div>
          </div>
          <ProgressBar :value="progressOf(threat)" :show-value="false" class="review-progress" />
          <div v-if="evaluationOf(threat)?.blockers.length" class="blocker-chip">
            <i class="pi pi-exclamation-triangle"></i>
            {{ evaluationOf(threat)?.blockers.length }} 项阻塞，无法通过会签
          </div>
        </article>

        <template v-if="retainedThreats.length">
          <h3 class="list-heading retained-heading">未受本次变更影响 · 结论保留（{{ retainedThreats.length }}）</h3>
          <article
            v-for="threat in retainedThreats"
            :key="threat.id"
            class="review-card retained"
            :class="{ selected: selectedThreatId === threat.id }"
            @click="selectedThreatId = threat.id"
          >
            <div class="review-card-head">
              <div>
                <span class="mono">{{ threat.code }} · v1.{{ threat.revision }}</span>
                <h2>{{ threat.title }}</h2>
              </div>
              <StatusTag :value="evaluationOf(threat)?.outcome ?? threat.reviewStatus" kind="review" />
            </div>
            <p class="retained-note">
              版本变更未触及该威胁，历史会签继续有效；证据/接受期限仍实时核对。
            </p>
          </article>
        </template>
      </section>

      <aside class="decision-panel">
        <template v-if="selectedThreat && selectedEvaluation">
          <div class="decision-head">
            <div>
              <span class="mono">{{ selectedThreat.code }} · v1.{{ selectedThreat.revision }}</span>
              <h2>{{ selectedThreat.title }}</h2>
            </div>
            <StatusTag :value="selectedEvaluation.outcome" kind="review" />
          </div>
          <p class="decision-description">{{ selectedThreat.description }}</p>

          <!-- 会签有效性核对：三方意见 / 证据有效期 / 风险接受期限 / 缓解冲突 同一次判断 -->
          <section class="validity-box">
            <div class="validity-head">
              <h3>会签有效性核对</h3>
              <span class="mono">基准 {{ selectedEvaluation.checkedAt.slice(0, 10) }}</span>
            </div>

            <div v-if="selectedEvaluation.outcome === 'approved'" class="validity-pass">
              <i class="pi pi-check-circle"></i>
              <div>
                <strong>会签有效</strong>
                <p>三方意见齐备，证据有效期、风险接受期限与缓解冲突核对全部通过。</p>
              </div>
            </div>

            <Message
              v-else
              :severity="selectedEvaluation.outcome === 'rejected' ? 'error' : 'warn'"
              :closable="false"
              class="validity-message"
            >
              {{
                selectedEvaluation.outcome === 'rejected'
                  ? '存在驳回意见，本威胁不能通过会签。'
                  : selectedEvaluation.outcome === 'blocked'
                    ? '三方虽已签字，但仍有阻塞项，不能得到通过结论（防止假通过）。'
                    : '会签尚未完成，以下条目需要补齐后才能通过。'
              }}
            </Message>

            <ul v-if="selectedEvaluation.blockers.length" class="blocker-list">
              <li v-for="blocker in selectedEvaluation.blockers" :key="blocker.id" class="blocker-item">
                <div class="blocker-top">
                  <StatusTag :value="blocker.severity" kind="severity" />
                  <span class="blocker-category">{{ categoryLabels[blocker.category] }}</span>
                </div>
                <strong class="blocker-title">{{ blocker.title }}</strong>
                <dl>
                  <div>
                    <dt>条目</dt>
                    <dd>{{ blocker.subject }}</dd>
                  </div>
                  <div>
                    <dt>当前值</dt>
                    <dd>{{ blocker.currentValue }}</dd>
                  </div>
                  <div>
                    <dt>待补动作</dt>
                    <dd class="action">{{ blocker.requiredAction }}</dd>
                  </div>
                </dl>
              </li>
            </ul>
          </section>

          <Button label="提交会签意见" icon="pi pi-pencil" class="decision-button" @click="openDecision" />

          <section class="decision-history">
            <h3>当前修订会签记录（v1.{{ selectedThreat.revision }}）</h3>
            <article v-for="decision in currentDecisions" :key="decision.id" class="decision-entry">
              <div>
                <strong>{{ decision.actor }}</strong>
                <span>{{ roleOptions.find((role) => role.value === decision.role)?.label }}</span>
              </div>
              <StatusTag :value="decision.decision" kind="review" />
              <p>{{ decision.comment }}</p>
              <time>{{ new Date(decision.createdAt).toLocaleString('zh-CN') }}</time>
            </article>
            <div v-if="currentDecisions.length === 0" class="empty-state">当前修订尚未提交会签意见。</div>
          </section>

          <section v-if="historicalGroups.length" class="decision-history historical">
            <h3>历史会签（版本升级后仍可查询）</h3>
            <div v-for="group in historicalGroups" :key="group.revision" class="history-group">
              <h4>v1.{{ group.revision }}</h4>
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
          </section>

          <div v-if="!isAffected(selectedThreat)" class="retained-banner">
            <i class="pi pi-info-circle"></i>
            该威胁不在当前版本受影响范围内，{{ latestVersion?.label ?? '当前版本' }} 不要求重新会签。
          </div>
        </template>
        <div v-else class="empty-state">从左侧选择一条威胁查看会签核对详情。</div>
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

.review-board {
  display: grid;
  grid-template-columns: minmax(0, 1.1fr) minmax(420px, 0.9fr);
  gap: 16px;
  align-items: start;
}

.review-list {
  display: grid;
  gap: 12px;
}

.list-heading {
  margin: 4px 0 -2px;
  font-size: 12px;
  color: #6b7689;
  letter-spacing: 0.04em;
}

.retained-heading {
  margin-top: 10px;
}

.review-card {
  padding: 16px;
  border: 1px solid #dde2ea;
  border-radius: 7px;
  background: #fff;
  cursor: pointer;
}

.review-card.retained {
  background: #f8faf9;
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

.blocker-chip {
  display: flex;
  align-items: center;
  gap: 7px;
  margin-top: 12px;
  padding: 7px 10px;
  border: 1px solid #f0cf9f;
  border-radius: 5px;
  color: #9a5b08;
  background: #fff8ee;
  font-size: 11px;
  font-weight: 600;
}

.retained-note {
  margin: 10px 0 0;
  color: #718079;
  font-size: 11px;
  line-height: 1.5;
}

.decision-panel {
  position: sticky;
  top: 82px;
  padding: 18px;
  border: 1px solid #dde2ea;
  border-radius: 7px;
  background: #fff;
  max-height: calc(100vh - 106px);
  overflow: auto;
}

.decision-description {
  margin: 14px 0 18px;
  color: #59657a;
  font-size: 13px;
  line-height: 1.65;
}

.validity-box {
  border: 1px solid #e3e7ee;
  border-radius: 7px;
  padding: 14px;
  background: #fbfcfe;
}

.validity-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}

.validity-head h3 {
  margin: 0;
  font-size: 13px;
}

.validity-head span {
  color: #8a94a6;
  font-size: 10px;
}

.validity-pass {
  display: flex;
  gap: 11px;
  padding: 12px;
  border: 1px solid #bfe3cf;
  border-radius: 6px;
  background: #f1faf5;
}

.validity-pass > i {
  color: #2f8f69;
  font-size: 18px;
}

.validity-pass strong {
  color: #236b4d;
  font-size: 13px;
}

.validity-pass p {
  margin: 3px 0 0;
  color: #4c6b5c;
  font-size: 11px;
  line-height: 1.5;
}

.validity-message {
  margin-bottom: 10px;
}

.blocker-list {
  display: grid;
  gap: 10px;
  margin: 10px 0 0;
  padding: 0;
  list-style: none;
}

.blocker-item {
  padding: 11px 12px;
  border: 1px solid #ecd9b6;
  border-left: 3px solid #d97706;
  border-radius: 5px;
  background: #fffdf8;
}

.blocker-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 7px;
}

.blocker-category {
  color: #9a7b3f;
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.05em;
}

.blocker-title {
  display: block;
  margin-bottom: 8px;
  font-size: 12px;
  color: #3a2c12;
}

.blocker-item dl {
  display: grid;
  gap: 5px;
  margin: 0;
}

.blocker-item dl > div {
  display: grid;
  grid-template-columns: 56px minmax(0, 1fr);
  gap: 8px;
}

.blocker-item dt {
  color: #8a7a55;
  font-size: 11px;
}

.blocker-item dd {
  margin: 0;
  color: #4c4433;
  font-size: 11px;
  line-height: 1.5;
}

.blocker-item dd.action {
  color: #94440a;
  font-weight: 600;
}

.decision-button {
  width: 100%;
  margin-top: 16px;
}

.decision-history {
  margin-top: 22px;
  padding-top: 18px;
  border-top: 1px solid #e5e9ef;
}

.decision-history.historical h4 {
  margin: 12px 0 6px;
  font-size: 11px;
  color: #79839a;
}

.decision-history h3 {
  margin: 0 0 12px;
  font-size: 13px;
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

.history-group + .history-group {
  margin-top: 6px;
  padding-top: 6px;
  border-top: 1px dashed #e5e9ef;
}

.retained-banner {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 16px;
  padding: 10px 12px;
  border-radius: 6px;
  color: #355a77;
  background: #eef5fb;
  font-size: 11px;
  line-height: 1.5;
}
</style>
