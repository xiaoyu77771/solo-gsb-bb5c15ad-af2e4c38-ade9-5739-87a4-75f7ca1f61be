import { describe, expect, it } from 'vitest';
import {
  formatChildZones,
  formatReverseDns,
  isValidNsName,
  nextOctetBoundary,
  parseNsLines,
  planReverseDns,
  reverseNameOf,
  zoneNameFor,
} from './reverseDns';
import { blockSize, parseCidr } from './ip';

const cidr = (s: string) => parseCidr(s)!;
const NS = ['ns1.example.com.', 'ns2.example.com.'];

describe('NS 名校验（带末尾点的绝对域名）', () => {
  it('接受合法的绝对域名', () => {
    expect(isValidNsName('ns1.example.com.')).toBe(true);
    expect(isValidNsName('NS1.Example.COM.')).toBe(true); // 大小写不敏感
    expect(isValidNsName('a.')).toBe(true); // 单标签
    expect(isValidNsName('ns-1.example.com.')).toBe(true); // 标签内含连字符
    expect(isValidNsName('0ns.9example.com.')).toBe(true); // 数字开头标签
    expect(isValidNsName(`${'a'.repeat(63)}.`)).toBe(true); // 标签长度上限 63
    // 主体总长上限 253
    expect(
      isValidNsName(`${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}.`),
    ).toBe(true);
  });

  it('拒绝非法域名', () => {
    expect(isValidNsName('ns1.example.com')).toBe(false); // 缺少末尾点
    expect(isValidNsName('')).toBe(false);
    expect(isValidNsName('.')).toBe(false); // 空主体
    expect(isValidNsName('ns1..example.com.')).toBe(false); // 空标签
    expect(isValidNsName('ns1.example.com..')).toBe(false); // 末尾空标签
    expect(isValidNsName('-ns1.example.com.')).toBe(false); // 连字符开头
    expect(isValidNsName('ns1-.example.com.')).toBe(false); // 连字符结尾
    expect(isValidNsName('ns1.exa_mple.com.')).toBe(false); // 下划线非法
    expect(isValidNsName('ns 1.example.com.')).toBe(false); // 含空格
    expect(isValidNsName(`${'a'.repeat(64)}.`)).toBe(false); // 标签超长
    // 主体总长 254 超限
    expect(
      isValidNsName(`${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(62)}.`),
    ).toBe(false);
  });
});

describe('NS 逐行解析', () => {
  it('空行跳过，合法行全部通过并保持顺序', () => {
    const { names, errors } = parseNsLines('ns1.example.com.\n\n  \nns2.example.com.\n');
    expect(errors).toEqual([]);
    expect(names).toEqual(NS);
  });

  it('非法行逐条报错（带行号），合法行仍被收集', () => {
    const { names, errors } = parseNsLines(
      'ns1.example.com.\nns2.example.com\n\nbad_name.\nns3.example.com.',
    );
    expect(names).toEqual(['ns1.example.com.', 'ns3.example.com.']);
    expect(errors).toHaveLength(2);
    expect(errors[0]).toContain('第 2 行');
    expect(errors[1]).toContain('第 4 行');
  });

  it('整段留空时不报错（由调用方按前缀决定是否允许）', () => {
    const { names, errors } = parseNsLines('  \n\n');
    expect(names).toEqual([]);
    expect(errors).toEqual([]);
  });
});

describe('反向名与区名', () => {
  it('reverseNameOf 生成完整反向名', () => {
    expect(reverseNameOf(cidr('10.0.0.7/32').base)).toBe('7.0.0.10.in-addr.arpa.');
    expect(reverseNameOf(0)).toBe('0.0.0.0.in-addr.arpa.');
    expect(reverseNameOf(0xffffffff)).toBe('255.255.255.255.in-addr.arpa.');
  });

  it('zoneNameFor 支持八位边界前缀', () => {
    expect(zoneNameFor(cidr('0.0.0.0/0'))).toBe('in-addr.arpa.');
    expect(zoneNameFor(cidr('10.0.0.0/8'))).toBe('10.in-addr.arpa.');
    expect(zoneNameFor(cidr('172.16.0.0/16'))).toBe('16.172.in-addr.arpa.');
    expect(zoneNameFor(cidr('192.168.8.0/24'))).toBe('8.168.192.in-addr.arpa.');
  });

  it('zoneNameFor 拒绝非八位边界前缀', () => {
    expect(() => zoneNameFor(cidr('10.0.0.0/25'))).toThrow();
    expect(() => zoneNameFor(cidr('10.0.0.0/9'))).toThrow();
  });

  it('nextOctetBoundary 归位到下一个八位边界', () => {
    expect(nextOctetBoundary(0)).toBe(0);
    expect(nextOctetBoundary(1)).toBe(8);
    expect(nextOctetBoundary(8)).toBe(8);
    expect(nextOctetBoundary(9)).toBe(16);
    expect(nextOctetBoundary(16)).toBe(16);
    expect(nextOctetBoundary(17)).toBe(24);
    expect(nextOctetBoundary(23)).toBe(24);
    expect(nextOctetBoundary(24)).toBe(24);
  });
});

describe('单个区（/0、/8、/16、/24）', () => {
  it.each([
    ['0.0.0.0/0', 'in-addr.arpa.'],
    ['10.0.0.0/8', '10.in-addr.arpa.'],
    ['172.16.0.0/16', '16.172.in-addr.arpa.'],
    ['192.168.8.0/24', '8.168.192.in-addr.arpa.'],
  ])('%s → 单个区 %s', (cidrText, zone) => {
    const plan = planReverseDns(cidr(cidrText), NS);
    expect(plan.kind).toBe('single');
    expect(plan.parentZone).toBeNull();
    expect(plan.parentRecords).toEqual([]);
    expect(plan.ptrHint).toBeNull();
    expect(plan.childZones).toHaveLength(1);
    expect(plan.childZones[0].zone).toBe(zone);
    expect(plan.childZones[0].cidr).toBe(cidrText);
    expect(plan.childZones[0].nsRecords).toEqual([
      '@ IN NS ns1.example.com.',
      '@ IN NS ns2.example.com.',
    ]);
  });
});

describe('拆分区域（其余 /1～/23）', () => {
  it('/23 拆为 2 个 /24 区', () => {
    const plan = planReverseDns(cidr('192.168.8.0/23'), NS);
    expect(plan.kind).toBe('split');
    expect(plan.childZones.map((z) => z.zone)).toEqual([
      '8.168.192.in-addr.arpa.',
      '9.168.192.in-addr.arpa.',
    ]);
    expect(plan.childZones.map((z) => z.cidr)).toEqual(['192.168.8.0/24', '192.168.9.0/24']);
  });

  it('/15 拆为 2 个 /16 区', () => {
    const plan = planReverseDns(cidr('172.20.0.0/15'), NS);
    expect(plan.childZones.map((z) => z.zone)).toEqual([
      '20.172.in-addr.arpa.',
      '21.172.in-addr.arpa.',
    ]);
  });

  it('/7 拆为 2 个 /8 区', () => {
    const plan = planReverseDns(cidr('254.0.0.0/7'), NS);
    expect(plan.childZones.map((z) => z.zone)).toEqual([
      '254.in-addr.arpa.',
      '255.in-addr.arpa.',
    ]);
  });

  it('/20 拆为 16 个 /24 区，按数值地址升序', () => {
    const plan = planReverseDns(cidr('10.32.0.0/20'), NS);
    expect(plan.childZones).toHaveLength(16);
    expect(plan.childZones[0].zone).toBe('0.32.10.in-addr.arpa.');
    expect(plan.childZones[15].zone).toBe('15.32.10.in-addr.arpa.');
    for (let i = 1; i < plan.childZones.length; i++) {
      expect(plan.childZones[i].base).toBe(plan.childZones[i - 1].base + 256);
    }
  });

  it('边界前缀数量：/1、/9、/17 均拆为 128 个区', () => {
    expect(planReverseDns(cidr('0.0.0.0/1'), NS).childZones).toHaveLength(128);
    expect(planReverseDns(cidr('10.0.0.0/9'), NS).childZones).toHaveLength(128);
    expect(planReverseDns(cidr('10.0.0.0/17'), NS).childZones).toHaveLength(128);
  });

  it('拆分结果恰好覆盖整个子网且互不重叠', () => {
    const subnet = cidr('10.32.0.0/20');
    const plan = planReverseDns(subnet, NS);
    expect(plan.childZones[0].base).toBe(subnet.base);
    const total = plan.childZones.length * blockSize(24);
    expect(total).toBe(blockSize(20));
    // 每个子区都是独立的八位边界区，数量即最小区域集合
    expect(plan.childZones.every((z) => z.cidr.endsWith('/24'))).toBe(true);
  });

  it('128.0.0.0/1 的高半区从 128.in-addr.arpa. 开始', () => {
    const plan = planReverseDns(cidr('128.0.0.0/1'), NS);
    expect(plan.childZones[0].zone).toBe('128.in-addr.arpa.');
    expect(plan.childZones[127].zone).toBe('255.in-addr.arpa.');
  });
});

describe('RFC 2317 无类别委派（/25～/31）', () => {
  it('/25 生成父区 NS、128 条 CNAME 与子区名', () => {
    const plan = planReverseDns(cidr('192.168.1.0/25'), NS);
    expect(plan.kind).toBe('rfc2317');
    expect(plan.parentZone).toBe('1.168.192.in-addr.arpa.');
    expect(plan.childZones).toHaveLength(1);
    expect(plan.childZones[0].zone).toBe('0-127.1.168.192.in-addr.arpa.');
    expect(plan.childZones[0].cidr).toBe('192.168.1.0/25');
    // 父区记录：2 条 NS + 128 条 CNAME
    expect(plan.parentRecords).toHaveLength(130);
    expect(plan.parentRecords[0]).toBe(
      '0-127.1.168.192.in-addr.arpa. IN NS ns1.example.com.',
    );
    expect(plan.parentRecords[1]).toBe(
      '0-127.1.168.192.in-addr.arpa. IN NS ns2.example.com.',
    );
    expect(plan.parentRecords[2]).toBe(
      '0.1.168.192.in-addr.arpa. IN CNAME 0.0-127.1.168.192.in-addr.arpa.',
    );
    expect(plan.parentRecords[129]).toBe(
      '127.1.168.192.in-addr.arpa. IN CNAME 127.0-127.1.168.192.in-addr.arpa.',
    );
  });

  it('/25 高半段子网的子区名与 CNAME 范围', () => {
    const plan = planReverseDns(cidr('192.168.1.128/25'), NS);
    expect(plan.childZones[0].zone).toBe('128-255.1.168.192.in-addr.arpa.');
    expect(plan.parentRecords[2]).toBe(
      '128.1.168.192.in-addr.arpa. IN CNAME 128.128-255.1.168.192.in-addr.arpa.',
    );
    expect(plan.parentRecords[129]).toBe(
      '255.1.168.192.in-addr.arpa. IN CNAME 255.128-255.1.168.192.in-addr.arpa.',
    );
  });

  it('/29 与 /31 的 CNAME 恰好覆盖子网全部地址', () => {
    const p29 = planReverseDns(cidr('10.0.0.8/29'), NS);
    expect(p29.childZones[0].zone).toBe('8-15.0.0.10.in-addr.arpa.');
    expect(p29.parentRecords.filter((r) => r.includes(' CNAME '))).toHaveLength(8);

    const p31 = planReverseDns(cidr('10.0.0.0/31'), NS);
    expect(p31.childZones[0].zone).toBe('0-1.0.0.10.in-addr.arpa.');
    const cnames = p31.parentRecords.filter((r) => r.includes(' CNAME '));
    expect(cnames).toEqual([
      '0.0.0.10.in-addr.arpa. IN CNAME 0.0-1.0.0.10.in-addr.arpa.',
      '1.0.0.10.in-addr.arpa. IN CNAME 1.0-1.0.0.10.in-addr.arpa.',
    ]);
  });

  it.each([25, 26, 27, 28, 29, 30, 31])('/%s 的 CNAME 数等于子网地址总数', (prefix) => {
    const subnet = cidr(`10.0.0.0/${prefix}`);
    const plan = planReverseDns(subnet, NS);
    const cnames = plan.parentRecords.filter((r) => r.includes(' CNAME '));
    expect(cnames).toHaveLength(blockSize(prefix));
  });
});

describe('/32 PTR 所有者提示', () => {
  it('生成单条 PTR 所有者提示，NS 可留空', () => {
    const plan = planReverseDns(cidr('10.0.0.7/32'), []);
    expect(plan.kind).toBe('ptr');
    expect(plan.parentZone).toBe('0.0.10.in-addr.arpa.');
    expect(plan.parentRecords).toEqual([]);
    expect(plan.childZones).toEqual([]);
    expect(plan.ptrHint).toEqual({
      owner: '7.0.0.10.in-addr.arpa.',
      parentZone: '0.0.10.in-addr.arpa.',
      record: '7.0.0.10.in-addr.arpa. IN PTR <主机名.>',
    });
  });

  it('地址上限边界：255.255.255.255/32', () => {
    const plan = planReverseDns(cidr('255.255.255.255/32'), []);
    expect(plan.ptrHint!.owner).toBe('255.255.255.255.in-addr.arpa.');
    expect(plan.ptrHint!.parentZone).toBe('255.255.255.in-addr.arpa.');
  });

  it('非 /32 前缀缺少 NS 时拒绝生成', () => {
    expect(() => planReverseDns(cidr('10.0.0.0/24'), [])).toThrow();
    expect(() => planReverseDns(cidr('10.0.0.0/25'), [])).toThrow();
  });
});

describe('片段格式化', () => {
  it('单区片段包含头部、$ORIGIN 与 NS 记录', () => {
    const plan = planReverseDns(cidr('192.168.8.0/24'), NS);
    const text = formatReverseDns(plan, '访客网络', '192.168.8.0/24');
    expect(text).toContain('; 反向 DNS 委派片段：访客网络 (192.168.8.0/24)');
    expect(text).toContain('$ORIGIN 8.168.192.in-addr.arpa.');
    expect(text).toContain('@ IN NS ns1.example.com.');
    expect(text).not.toContain('父区记录');
  });

  it('RFC 2317 片段分段展示父区记录与需创建的子区', () => {
    const plan = planReverseDns(cidr('192.168.1.0/25'), NS);
    const text = formatReverseDns(plan, '办公有线', '192.168.1.0/25');
    const parentIdx = text.indexOf('; 父区记录');
    const childIdx = text.indexOf('; 需创建的子区');
    expect(parentIdx).toBeGreaterThan(-1);
    expect(childIdx).toBeGreaterThan(parentIdx);
    expect(text).toContain('0-127.1.168.192.in-addr.arpa. IN NS ns1.example.com.');
    expect(text).toContain(
      '127.1.168.192.in-addr.arpa. IN CNAME 127.0-127.1.168.192.in-addr.arpa.',
    );
    expect(text).toContain('$ORIGIN 0-127.1.168.192.in-addr.arpa.');
  });

  it('拆分片段为每个子区生成 $ORIGIN 块', () => {
    const plan = planReverseDns(cidr('10.32.0.0/20'), NS);
    const text = formatChildZones(plan.childZones);
    expect(text.split('$ORIGIN')).toHaveLength(17); // 16 个子区
    expect(text).toContain('; 10.32.0.0/24 → 0.32.10.in-addr.arpa.');
    expect(text).toContain('; 10.32.15.0/24 → 15.32.10.in-addr.arpa.');
  });

  it('/32 片段仅含 PTR 所有者提示', () => {
    const plan = planReverseDns(cidr('10.0.0.7/32'), []);
    const text = formatReverseDns(plan, 'loopback', '10.0.0.7/32');
    expect(text).toContain('7.0.0.10.in-addr.arpa. IN PTR <主机名.>');
    expect(text).toContain('0.0.10.in-addr.arpa.');
    expect(text).not.toContain('$ORIGIN');
  });
});
