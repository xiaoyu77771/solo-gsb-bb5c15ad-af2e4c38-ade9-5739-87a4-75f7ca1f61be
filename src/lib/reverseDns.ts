/**
 * 反向 DNS（in-addr.arpa）BIND 委派片段生成。
 *
 * 按子网前缀生成可复制的委派片段：
 *  - /0、/8、/16、/24：生成单个 in-addr.arpa 区；
 *  - 其余 /1～/23：拆分为下一个八位边界（/8、/16 或 /24）上的最小区域集合；
 *  - /25～/31：RFC 2317 无类别委派——父区 NS 记录 + 覆盖子网全部地址的 CNAME + 子区名；
 *  - /32：单条 PTR 所有者提示（无需 NS，可留空）。
 *
 * 所有区域与记录均按数值地址升序输出。
 * 纯本地计算，不修改规划、不产生历史记录。
 */
import { Cidr, blockSize, cidrToString, lastAddr, networkOf } from './ip';

/** 需创建的子区 */
export interface ChildZonePlan {
  /** 子区名（绝对域名，带末尾点） */
  zone: string;
  /** 覆盖范围起始地址（uint32），用于按数值地址排序 */
  base: number;
  /** 对应 CIDR 文本（展示用） */
  cidr: string;
  /** 区文件中的 NS 记录行（保持用户填写顺序） */
  nsRecords: string[];
}

/** /32 的 PTR 所有者提示 */
export interface PtrHint {
  /** PTR 记录所有者名（绝对域名，带末尾点） */
  owner: string;
  /** 应添加该记录的父区 */
  parentZone: string;
  /** 完整提示记录文本 */
  record: string;
}

export type ReverseDnsKind = 'single' | 'split' | 'rfc2317' | 'ptr';

export interface ReverseDnsPlan {
  kind: ReverseDnsKind;
  /** 父区名（rfc2317 / ptr 时为所在 /24 区，否则为 null） */
  parentZone: string | null;
  /** 需追加到父区的记录（NS 委派 + CNAME），按数值地址升序 */
  parentRecords: string[];
  /** 需创建的子区，按数值地址升序 */
  childZones: ChildZonePlan[];
  /** /32 的 PTR 所有者提示 */
  ptrHint: PtrHint | null;
}

/** 单个 DNS 标签：字母数字开头结尾，中间可含连字符，1-63 字符 */
const LABEL_RE = /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/;

/** 是否为带末尾点的绝对域名（如 ns1.example.com.） */
export function isValidNsName(line: string): boolean {
  const text = line.trim();
  if (!text.endsWith('.')) return false;
  const body = text.slice(0, -1);
  if (body.length === 0 || body.length > 253) return false;
  return body.split('.').every((label) => label.length >= 1 && label.length <= 63 && LABEL_RE.test(label));
}

export interface NsParseResult {
  /** 全部合法的 NS（保持填写顺序，空行已跳过） */
  names: string[];
  /** 逐行错误信息（带行号）；非空时不应生成结果 */
  errors: string[];
}

/** 逐行解析权威 NS：空行跳过；任一非空行非法即按行收集错误。 */
export function parseNsLines(text: string): NsParseResult {
  const names: string[] = [];
  const errors: string[] = [];
  text.split('\n').forEach((raw, i) => {
    const line = raw.trim();
    if (!line) return;
    if (!isValidNsName(line)) {
      errors.push(`第 ${i + 1} 行：NS 必须是带末尾点的绝对域名（如 ns1.example.com.）：${line}`);
      return;
    }
    names.push(line);
  });
  return { names, errors };
}

/** 地址的完整反向名：d.c.b.a.in-addr.arpa. */
export function reverseNameOf(addr: number): string {
  return (
    [addr & 255, (addr >>> 8) & 255, (addr >>> 16) & 255, (addr >>> 24) & 255].join('.') +
    '.in-addr.arpa.'
  );
}

/** 八位边界前缀（0/8/16/24）CIDR 的 in-addr.arpa 区名（绝对，带末尾点）。 */
export function zoneNameFor(c: Cidr): string {
  const a = (c.base >>> 24) & 255;
  const b = (c.base >>> 16) & 255;
  const d = (c.base >>> 8) & 255;
  switch (c.prefix) {
    case 0:
      return 'in-addr.arpa.';
    case 8:
      return `${a}.in-addr.arpa.`;
    case 16:
      return `${b}.${a}.in-addr.arpa.`;
    case 24:
      return `${d}.${b}.${a}.in-addr.arpa.`;
    default:
      throw new Error(`区名仅支持八位边界前缀（0/8/16/24）：/${c.prefix}`);
  }
}

/** 下一个八位边界前缀：/0→/0，/1～/8→/8，/9～/16→/16，/17～/24→/24 */
export function nextOctetBoundary(prefix: number): number {
  return Math.min(24, Math.ceil(prefix / 8) * 8);
}

function makeChildZone(zone: string, c: Cidr, ns: string[]): ChildZonePlan {
  return {
    zone,
    base: c.base,
    cidr: cidrToString(c),
    nsRecords: ns.map((n) => `@ IN NS ${n}`),
  };
}

/**
 * 计算反向 DNS 委派计划。ns 须已通过 parseNsLines 校验；
 * 非 /32 前缀至少需要一个 NS，否则抛出异常。
 */
export function planReverseDns(subnet: Cidr, ns: string[]): ReverseDnsPlan {
  const p = subnet.prefix;
  if (p !== 32 && ns.length === 0) {
    throw new Error('至少需要一个权威 NS（仅 /32 可留空）');
  }

  if (p === 32) {
    // 单条 PTR 所有者提示：在所在 /24 父区中为该地址添加 PTR 记录
    const parentZone = zoneNameFor({ base: networkOf(subnet.base, 24), prefix: 24 });
    const owner = reverseNameOf(subnet.base);
    return {
      kind: 'ptr',
      parentZone,
      parentRecords: [],
      childZones: [],
      ptrHint: { owner, parentZone, record: `${owner} IN PTR <主机名.>` },
    };
  }

  if (p >= 25) {
    // RFC 2317 无类别委派：父区（所在 /24）中放置子区 NS 与逐地址 CNAME
    const parentZone = zoneNameFor({ base: networkOf(subnet.base, 24), prefix: 24 });
    const first = subnet.base & 255;
    const last = lastAddr(subnet) & 255;
    const childZone = `${first}-${last}.${parentZone}`;
    const parentRecords = ns.map((n) => `${childZone} IN NS ${n}`);
    for (let d = first; d <= last; d++) {
      parentRecords.push(`${d}.${parentZone} IN CNAME ${d}.${childZone}`);
    }
    return {
      kind: 'rfc2317',
      parentZone,
      parentRecords,
      childZones: [makeChildZone(childZone, subnet, ns)],
      ptrHint: null,
    };
  }

  // /0～/24：八位边界前缀生成单个区；其余拆分为下一个八位边界上的最小区域集合
  const boundary = nextOctetBoundary(p);
  const count = blockSize(p) / blockSize(boundary);
  const size = blockSize(boundary);
  const childZones: ChildZonePlan[] = [];
  for (let i = 0; i < count; i++) {
    const c: Cidr = { base: (subnet.base + i * size) >>> 0, prefix: boundary };
    childZones.push(makeChildZone(zoneNameFor(c), c, ns));
  }
  childZones.sort((a, b) => a.base - b.base);
  return {
    kind: p === boundary ? 'single' : 'split',
    parentZone: null,
    parentRecords: [],
    childZones,
    ptrHint: null,
  };
}

/** 子区片段文本：注释行（CIDR → 区名）+ $ORIGIN + NS 记录。 */
export function formatChildZones(zones: ChildZonePlan[]): string {
  return zones
    .map((z) => [`; ${z.cidr} → ${z.zone}`, `$ORIGIN ${z.zone}`, ...z.nsRecords].join('\n'))
    .join('\n\n');
}

/** 生成可复制的完整 BIND 委派片段（父区记录与需创建的子区分段展示）。 */
export function formatReverseDns(plan: ReverseDnsPlan, allocName: string, cidrText: string): string {
  const header = `; 反向 DNS 委派片段：${allocName} (${cidrText})`;
  if (plan.ptrHint) {
    return [
      header,
      `; 在父区 ${plan.ptrHint.parentZone} 中为以下所有者添加 PTR 记录：`,
      plan.ptrHint.record,
    ].join('\n');
  }
  const sections: string[] = [header];
  if (plan.parentZone && plan.parentRecords.length > 0) {
    sections.push(
      `; 父区记录（追加到 ${plan.parentZone}，按数值地址升序）：\n${plan.parentRecords.join('\n')}`,
    );
  }
  if (plan.childZones.length > 0) {
    sections.push(
      `; 需创建的子区（共 ${plan.childZones.length} 个，按数值地址升序）：\n${formatChildZones(plan.childZones)}`,
    );
  }
  return sections.join('\n\n');
}
