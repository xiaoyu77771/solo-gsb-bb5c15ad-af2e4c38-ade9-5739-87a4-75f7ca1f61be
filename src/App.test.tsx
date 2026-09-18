import { describe, expect, it } from 'vitest';
import { renderToString } from 'react-dom/server';
import { createElement } from 'react';
import App from './App';
import ReverseDnsModal from './components/ReverseDnsModal';

describe('App 冒烟测试', () => {
  it('组件树可整体渲染', () => {
    const html = renderToString(createElement(App));
    expect(html).toContain('IPv4 子网规划台');
    expect(html).toContain('根网段');
    expect(html).toContain('地址空间树');
    expect(html).toContain('新建分配');
    expect(html).toContain('前缀策略校验');
  });

  it('反向 DNS 弹窗可渲染', () => {
    const alloc = {
      id: 'a1',
      name: '办公无线',
      kind: 'subnet' as const,
      prefix: 24,
      cidr: '192.168.8.0/24',
    };
    const html = renderToString(
      createElement(ReverseDnsModal, { alloc, onClose: () => {} }),
    );
    expect(html).toContain('反向 DNS 委派片段');
    expect(html).toContain('192.168.8.0/24');
    expect(html).toContain('ns1.example.com.');
  });
});
