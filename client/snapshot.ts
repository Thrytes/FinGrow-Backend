import type { DesktopStoredDocument, DesktopVaultState } from '../../desktop/src/lib/desktop-store'
import type { FinGrowSplitExpense } from '../../desktop/src/app/(frontend)/FinGrowApp'

export type SyncRecord = Record<string, unknown> & { id: string | number }
export type SyncDataset = { formatVersion: 1; collections: Record<string, SyncRecord[]> }

const clone = <T>(value: T): T => value === undefined ? value : JSON.parse(JSON.stringify(value)) as T
const same = (left: unknown, right: unknown) => JSON.stringify(left) === JSON.stringify(right)
const idOf = (record: SyncRecord) => String(record.id)

export function mergeSyncDatasets(
  baseline: SyncDataset | null,
  local: SyncDataset,
  remote: SyncDataset | null,
): SyncDataset {
  const baseCollections = baseline?.collections ?? {}
  const remoteCollections = remote?.collections ?? {}
  const collectionNames = new Set([
    ...Object.keys(baseCollections),
    ...Object.keys(local.collections),
    ...Object.keys(remoteCollections),
  ])
  const collections: Record<string, SyncRecord[]> = {}

  for (const collection of collectionNames) {
    const base = new Map((baseCollections[collection] ?? []).map((item) => [idOf(item), item]))
    const mine = new Map((local.collections[collection] ?? []).map((item) => [idOf(item), item]))
    const theirs = new Map((remoteCollections[collection] ?? []).map((item) => [idOf(item), item]))
    const ids = new Set([...base.keys(), ...mine.keys(), ...theirs.keys()])
    const merged: SyncRecord[] = []

    for (const id of ids) {
      const before = base.get(id)
      const localItem = mine.get(id)
      const remoteItem = theirs.get(id)
      if (same(localItem, remoteItem)) {
        if (localItem) merged.push(clone(localItem))
        continue
      }
      if (same(localItem, before)) {
        if (remoteItem) merged.push(clone(remoteItem))
        continue
      }
      if (same(remoteItem, before)) {
        if (localItem) merged.push(clone(localItem))
        continue
      }
      if (!localItem || !remoteItem) {
        // A concurrent edit wins over a deletion so that one device cannot
        // silently discard another device's recent financial change.
        if (localItem || remoteItem) merged.push(clone(localItem ?? remoteItem!))
        continue
      }
      merged.push(mergeRecord(before, localItem, remoteItem))
    }
    collections[collection] = merged
  }
  return { formatVersion: 1, collections }
}

function mergeRecord(
  baseline: SyncRecord | undefined,
  local: SyncRecord,
  remote: SyncRecord,
): SyncRecord {
  const keys = new Set([
    ...Object.keys(baseline ?? {}),
    ...Object.keys(local),
    ...Object.keys(remote),
  ])
  const result: SyncRecord = { id: local.id }
  for (const key of keys) {
    if (key === 'id') continue
    const baseValue = baseline?.[key]
    const localValue = local[key]
    const remoteValue = remote[key]
    if (same(localValue, remoteValue)) {
      if (localValue !== undefined) result[key] = clone(localValue)
    } else if (same(localValue, baseValue)) {
      if (remoteValue !== undefined) result[key] = clone(remoteValue)
    } else if (same(remoteValue, baseValue)) {
      if (localValue !== undefined) result[key] = clone(localValue)
    } else if (
      (key === 'balanceMinor' || key === 'outstandingMinor') &&
      typeof baseValue === 'number' &&
      typeof localValue === 'number' &&
      typeof remoteValue === 'number'
    ) {
      result[key] = baseValue + (localValue - baseValue) + (remoteValue - baseValue)
    } else if (isObject(localValue) && isObject(remoteValue)) {
      result[key] = { ...remoteValue, ...localValue }
    } else {
      result[key] = clone(localValue)
    }
  }
  return result
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === 'object' && !Array.isArray(value)

export function exportDesktopDataset(state: DesktopVaultState): SyncDataset {
  const collections: Record<string, SyncRecord[]> = {
    users: [{ ...state.currentUser }],
    profiles: state.profiles.map((item) => ({
      id: item.id,
      userId: state.currentUser.id,
      name: item.name,
      kind: item.kind,
      currency: item.baseCurrency,
      accent: item.accent,
    })),
    accounts: state.accounts.map((item) => ({
      ...item,
      type: item.type === 'credit-card' ? 'credit' : item.type,
      profileId: item.profile,
      profile: undefined,
    })),
    cards: state.cards.map((item) => ({
      id: item.id,
      profileId: item.profile,
      name: item.nickname,
      issuer: item.issuer,
      network: item.network,
      kind: item.kind === 'prepaid' ? 'loyalty' : item.kind,
      lastFour: item.lastFour,
      expiryMonth: item.expiryMonth,
      expiryYear: item.expiryYear,
      limitMinor: item.limitMinor,
      outstandingMinor: item.outstandingMinor,
      paymentDueAt: item.paymentDueAt ?? null,
    })),
    transactions: state.transactions.map((item) => ({
      ...item,
      profileId: item.profile,
      accountId: item.account,
      destinationAccountId: item.destinationAccount ?? null,
      notes: item.note ?? null,
    })),
    plans: state.plans.map((item) => ({ ...item, profileId: item.profile })),
    splitGroups: state.splitGroups.map((item) => ({
      id: item.id,
      profileId: item.profile,
      name: item.name,
      membersJson: JSON.stringify(item.members),
      createdAt: item.createdAt ?? new Date(0).toISOString(),
    })),
    splitExpenses: state.splitGroups.flatMap((group) =>
      (group.expenses ?? []).map((expense: FinGrowSplitExpense) => ({
        id: expense.id,
        groupId: group.id,
        title: expense.title,
        amountMinor: expense.amountMinor,
        category: expense.category,
        paidByName: expense.paidBy,
        occurredAt: expense.date,
        settledAt: expense.settledAt ?? null,
      })),
    ),
    documents: state.documents.map((item: DesktopStoredDocument) => ({ ...item, profileId: item.profile })),
    preferences: [{
      id: state.profiles[0]?.id ?? 'desktop-preferences',
      activeProfileId: state.profiles[0]?.id,
      currency: state.profiles[0]?.baseCurrency ?? 'INR',
      ...state.preferences,
      notificationsEnabled: state.preferences.notifications,
    }],
    goals: [],
    subscriptions: [],
    emis: [],
    notificationCandidates: [],
  }
  for (const [name, items] of Object.entries(state.syncExtras ?? {})) {
    const records = items as SyncRecord[]
    if (name in collections) collections[name] = [...records, ...collections[name]]
    else collections[name] = records
  }
  const baseline = state.sync?.baseline as SyncDataset | null | undefined
  for (const [name, rows] of Object.entries(collections)) {
    const previous = new Map((baseline?.collections[name] ?? []).map((row) => [idOf(row), row]))
    collections[name] = rows.map((row) => ({ ...previous.get(idOf(row)), ...row }))
  }
  return { formatVersion: 1, collections }
}

export function importDesktopDataset(state: DesktopVaultState, dataset: SyncDataset): void {
  const collections = dataset.collections
  const accounts = collections.accounts ?? []
  const cards = collections.cards ?? []
  const transactions = collections.transactions ?? []
  const plans = collections.plans ?? []
  const documents = collections.documents ?? []
  const groups = collections.splitGroups ?? []
  const expenses = collections.splitExpenses ?? []

  state.currentUser = (collections.users?.[0] as DesktopVaultState['currentUser']) ?? state.currentUser
  state.profiles = (collections.profiles ?? []).map((row) => ({
    id: row.id as string,
    name: String(row.name ?? 'Personal'),
    kind: (['personal', 'household', 'business'].includes(String(row.kind)) ? row.kind : 'personal') as DesktopVaultState['profiles'][number]['kind'],
    baseCurrency: String(row.currency ?? row.baseCurrency ?? 'INR'),
    accent: (row.accent ?? 'blue') as DesktopVaultState['profiles'][number]['accent'],
  }))
  if (!state.profiles.length) state.profiles = [{ id: state.sync?.profileId ?? crypto.randomUUID(), name: 'Personal', kind: 'personal', baseCurrency: 'INR', accent: 'blue' }]
  state.accounts = accounts.map((row) => ({
    id: row.id as string,
    profile: (row.profileId ?? row.profile) as string,
    name: String(row.name ?? ''),
    institution: String(row.institution ?? ''),
    type: (row.type === 'credit' ? 'credit-card' : row.type) as DesktopVaultState['accounts'][number]['type'],
    currency: String(row.currency ?? 'INR'),
    balanceMinor: Number(row.balanceMinor ?? 0),
    lastFour: row.lastFour as string | null | undefined,
  })).filter((row) => state.profiles.some((profile) => String(profile.id) === String(row.profile)))
  state.cards = cards.map((row) => ({
    id: row.id as string,
    profile: (row.profileId ?? row.profile) as string,
    nickname: String(row.name ?? row.nickname ?? 'Card'),
    issuer: String(row.issuer ?? ''),
    network: (['visa', 'mastercard', 'rupay', 'amex', 'other'].includes(String(row.network ?? row.cardNetwork ?? '').toLowerCase())
      ? String(row.network ?? row.cardNetwork).toLowerCase()
      : 'other') as DesktopVaultState['cards'][number]['network'],
    kind: (row.kind === 'loyalty' ? 'prepaid' : row.kind ?? 'credit') as DesktopVaultState['cards'][number]['kind'],
    lastFour: String(row.lastFour ?? ''),
    expiryMonth: row.expiryMonth == null ? undefined : Number(row.expiryMonth),
    expiryYear: row.expiryYear == null ? undefined : Number(row.expiryYear),
    limitMinor: Number(row.limitMinor ?? 0),
    outstandingMinor: Number(row.outstandingMinor ?? 0),
    paymentDueAt: row.paymentDueAt as string | null | undefined,
  }))
  state.transactions = transactions.map((row) => ({
    id: row.id as string,
    profile: (row.profileId ?? row.profile) as string,
    account: (row.accountId ?? row.account) as string,
    destinationAccount: (row.destinationAccountId ?? row.destinationAccount ?? null) as string | null,
    type: row.type as DesktopVaultState['transactions'][number]['type'],
    amountMinor: Number(row.amountMinor ?? 0),
    category: String(row.category ?? 'other'),
    note: (row.notes ?? row.note ?? null) as string | null,
    occurredAt: String(row.occurredAt ?? new Date().toISOString()),
  }))
  state.plans = plans.map((row) => ({
    id: row.id as string,
    profile: (row.profileId ?? row.profile) as string,
    name: String(row.name ?? 'Freedom Plan'),
    currentAge: Number(row.currentAge ?? 30),
    retirementAge: Number(row.retirementAge ?? 50),
    currentInvestmentMinor: Number(row.currentInvestmentMinor ?? 0),
    monthlyInvestmentMinor: Number(row.monthlyInvestmentMinor ?? 0),
    monthlyExpenseMinor: Number(row.monthlyExpenseMinor ?? 0),
    annualReturnRate: Number(row.annualReturnRate ?? 12),
    inflationRate: Number(row.inflationRate ?? 6),
    withdrawalRate: Number(row.withdrawalRate ?? 4),
  }))
  const expenseMap = new Map<string, DesktopVaultState['splitGroups'][number]['expenses']>()
  for (const row of expenses) {
    const groupId = String(row.groupId)
    const list = expenseMap.get(groupId) ?? []
    list.push({
      id: row.id as string,
      title: String(row.title ?? ''),
      amountMinor: Number(row.amountMinor ?? 0),
      category: row.category as FinGrowSplitExpense['category'],
      paidBy: String(row.paidByName ?? row.paidBy ?? ''),
      date: String(row.occurredAt ?? row.date ?? new Date().toISOString()),
      settledAt: row.settledAt as string | null | undefined,
    })
    expenseMap.set(groupId, list)
  }
  state.splitGroups = groups.map((row) => {
    let members: Array<{ name: string; email?: string | null }> = []
    try { members = JSON.parse(String(row.membersJson ?? row.members ?? '[]')) as typeof members } catch {}
    return {
      id: row.id as string,
      profile: (row.profileId ?? row.profile) as string,
      name: String(row.name ?? 'Group'),
      members,
      expenses: expenseMap.get(String(row.id)) ?? [],
      createdAt: String(row.createdAt ?? new Date(0).toISOString()),
    }
  })
  state.documents = documents.map((row) => ({
    id: row.id as string,
    profile: (row.profileId ?? row.profile) as string,
    title: String(row.title ?? ''),
    category: String(row.category ?? 'other'),
    createdAt: String(row.createdAt ?? new Date().toISOString()),
    fileName: String(row.fileName ?? ''),
    fileSize: Number(row.fileSize ?? 0),
    mimeType: String(row.mimeType ?? 'application/octet-stream'),
    renewalAt: row.renewalAt as string | null | undefined,
    updatedAt: String(row.updatedAt ?? new Date().toISOString()),
    fileData: String(row.fileData ?? ''),
  }))
  const preferences = collections.preferences?.[0]
  if (preferences) {
    if (preferences.currency) {
      state.profiles = state.profiles.map((profile, index) => index === 0
        ? { ...profile, baseCurrency: String(preferences.currency) }
        : profile)
    }
    state.preferences = {
      autoLockMinutes: (['1', '5', '10', '30'].includes(String(preferences.autoLockMinutes))
        ? String(preferences.autoLockMinutes)
        : '10') as DesktopVaultState['preferences']['autoLockMinutes'],
      privacyMode: Boolean(preferences.privacyMode ?? false),
      localAI: Boolean(preferences.localAI ?? false),
      notifications: Boolean(preferences.notificationsEnabled ?? preferences.notifications ?? true),
      density: (preferences.density ?? 'comfortable') as DesktopVaultState['preferences']['density'],
    }
  }

  const supported = new Set(['users', 'profiles', 'accounts', 'cards', 'transactions', 'plans', 'splitGroups', 'splitExpenses', 'documents', 'preferences'])
  state.syncExtras = Object.fromEntries(Object.entries(collections).filter(([name]) => !supported.has(name)))
}

