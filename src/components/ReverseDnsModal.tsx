import { useState } from 'react';
import { Allocation } from '../lib/model';
import { parseCidr } from '../lib/ip';
import {
  ReverseDnsPlan,
  formatChildZones,
  formatReverseDns,
  parseNsLines,
  planReverseDns,
} from '../lib/reverseDns';

interface Props {
  alloc: Allocation;
  onClose: () => void;
}

/**
 * 反向 DNS 委派片段弹窗：纯本地计算，不修改规划与历史。
 * 逐行填写权威 NS（/32 可留空），非空项必须是带末尾点的绝对域名；
 * 任一 NS 非法时不生成结果。
 */
export default function ReverseDnsModal({ alloc, onClose }: Props) {
  const subnet = parseCidr(alloc.cidr)!;
  const isPtrOnly = subnet.prefix === 32;
  const [text, setText] = useState('');
  const [errors, setErrors] = useState<string[]>([]);
  const [plan, setPlan] = useState<ReverseDnsPlan | null>(null);
  const [copied, setCopied] = useState(false);

  const generate = () => {
    const { names, errors: errs } = parseNsLines(text);
    const allErrs = [...errs];
    if (!isPtrOnly && names.length === 0) {
      allErrs.push('请至少填写一个权威 NS（仅 /32 可留空）');
    }
    setErrors(allErrs);
    setCopied(false);
    if (allErrs.length > 0) {
      setPlan(null);
      return;
    }
    setPlan(planReverseDns(subnet, names));
  };

  const snippet = plan ? formatReverseDns(plan, alloc.name, alloc.cidr) : '';
  const summary = plan
    ? plan.kind === 'ptr'
      ? 'PTR 所有者提示 1 条'
      : plan.kind === 'rfc2317'
        ? `父区记录 ${plan.parentRecords.length} 条 · 需创建子区 1 个`
        : `需创建子区 ${plan.childZones.length} 个`
    : '';

  const copySnippet = async () => {
    try {
      await navigator.clipboard.writeText(snippet);
    } catch {
      // 剪贴板 API 不可用（如非安全上下文）时回退
      const ta = document.createElement('textarea');
      ta.value = snippet;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopied(true);
  };

  const rowsFor = (text: string) => Math.min(Math.max(text.split('\n').length, 2), 14);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal wide" onClick={(e) => e.stopPropagation()}>
        <h3>反向 DNS 委派片段：{alloc.name}</h3>
        <p className="muted">
          子网 <code>{alloc.cidr}</code>。逐行填写权威 NS，非空项必须是带末尾点的绝对域名（如{' '}
          <code>ns1.example.com.</code>）{isPtrOnly ? '；/32 可留空' : ''}。/0、/8、/16、/24
          生成单个 in-addr.arpa 区；其余 /1～/23 拆分为下一个八位边界上的最小区域集合；/25～/31 按
          RFC 2317 生成父区 NS 委派与覆盖子网全部地址的 CNAME；/32 生成单条 PTR
          所有者提示。任一 NS 非法时不生成。纯本地计算，不修改规划与历史。
        </p>
        <label className="field">
          <span>权威 NS（每行一个，带末尾点{isPtrOnly ? '，可留空' : ''}）</span>
          <textarea
            autoFocus
            rows={4}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={'例如：\nns1.example.com.\nns2.example.com.'}
            spellCheck={false}
          />
        </label>
        {errors.length > 0 && (
          <ul className="errors">
            {errors.map((er, i) => (
              <li key={i}>{er}</li>
            ))}
          </ul>
        )}
        {plan && (
          <div className="dhcp-result">
            <div className="dhcp-result-head">
              <span>{summary}</span>
              <button className="btn small" onClick={copySnippet}>
                {copied ? '已复制 ✓' : '复制片段'}
              </button>
            </div>
            {plan.ptrHint && (
              <>
                <p className="rdns-section-title">
                  PTR 所有者提示（在父区 {plan.ptrHint.parentZone} 中添加）
                </p>
                <textarea readOnly rows={2} value={plan.ptrHint.record} />
              </>
            )}
            {plan.parentZone && plan.parentRecords.length > 0 && (
              <>
                <p className="rdns-section-title">
                  父区记录（追加到 {plan.parentZone}，按数值地址升序）
                </p>
                <textarea readOnly rows={rowsFor(plan.parentRecords.join('\n'))} value={plan.parentRecords.join('\n')} />
              </>
            )}
            {plan.childZones.length > 0 && (
              <>
                <p className="rdns-section-title">
                  需创建的子区（{plan.childZones.length} 个，按数值地址升序）
                </p>
                <textarea readOnly rows={rowsFor(formatChildZones(plan.childZones))} value={formatChildZones(plan.childZones)} />
              </>
            )}
          </div>
        )}
        <div className="modal-actions">
          <button className="btn" onClick={onClose}>
            关闭
          </button>
          <button className="btn primary" onClick={generate}>
            生成片段
          </button>
        </div>
      </div>
    </div>
  );
}
