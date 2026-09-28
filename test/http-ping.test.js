import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import {
  buildAgentConfig,
  describeAgentConfig,
  serializeAgentConfig,
  validateAgentConfigInput,
  validatePingNode
} from '../src/utils/agentConfig.js';
import { normalizeInstallPingMode, validatePingNode as validateFrontendNode } from '../src/frontend/utils/pingNode.js';

test('前后端接受完整 HTTP/HTTPS 网址并保留路径和查询参数', () => {
  for (const validate of [validatePingNode, validateFrontendNode]) {
    for (const target of [
      'https://example.com/health/check?value=a%2Bb&next=ready',
      'http://127.0.0.1:8080/ready',
      'https://[2001:db8::1]:8443/check',
      'https://example.com/检查',
      'example.com:443',
      '[2001:db8::1]:443',
      '0',
      ''
    ]) {
      assert.equal(validate(target).valid, true, target);
    }
    assert.deepEqual(validate('HTTPS://Example.COM/Health'), { valid: true, value: 'https://example.com/Health' });
  }
});

test('拒绝无效协议、带凭据的网址、片段、非法端口和超长网址', () => {
  for (const validate of [validatePingNode, validateFrontendNode]) {
    for (const target of [
      'ftp://example.com/file',
      'file:///etc/passwd',
      'https://user:password@example.com/',
      'https://example.com/#fragment',
      'http://example.com:0/',
      'http://example.com:65536/',
      'http://example..com/',
      'http://example.com/with space',
      'http://example.com/with\\backslash',
      'https://example.com/' + 'x'.repeat(512)
    ]) {
      assert.equal(validate(target).valid, false, target);
    }
  }
});

test('HTTP 模式配置下发保留网址字符并防止查询参数混入协议字段', async () => {
  const target = "https://example.com/health/a'b!()?q=a+b&ping_mode=icmp&reset_day=31";
  const server = { collect_interval: 0, report_interval: 60, reset_day: 1, ping_mode: 'http', custom_ct: target, custom_cu: '0' };
  assert.equal(validateAgentConfigInput(server).config.ping_mode, 'http');
  const descriptor = await describeAgentConfig(server, { custom_ct: 'example.org', custom_cu: 'example.org', node_1: 'https://example.net/check' });
  const params = new URLSearchParams(descriptor.serialized);
  assert.equal(params.get('schema_version'), '8');
  assert.equal(params.get('ping_mode'), 'http');
  assert.equal(params.get('reset_day'), '1');
  assert.equal(params.get('custom_ct'), new URL(target).href);
  assert.equal(params.get('custom_cu'), '');
  assert.equal(params.get('node_1'), 'https://example.net/check');
  assert.equal(params.getAll('ping_mode').length, 1);
  assert.equal(descriptor.md5, createHash('md5').update(descriptor.serialized).digest('hex'));
  assert.match(descriptor.serialized, /^[A-Za-z0-9_=&.,:%+\-*?\[\]]*$/);
});

test('旧探针继续接收兼容配置，HTTP 模式不伪装成 TCP 测量', () => {
  for (const schema of [3, 4, 5, 6, 7]) {
    const config = buildAgentConfig({ ping_mode: 'http', custom_ct: 'https://example.com/ready' }, { node_1: 'example.net' }, schema);
    assert.equal(config.schema_version, schema);
    assert.equal(config.custom_ct, '');
    assert.equal(config.node_1 || '', '');
    if (schema >= 6) assert.equal(config.ping_mode, 'tcp');
    else assert.equal(Object.hasOwn(config, 'ping_mode'), false);
  }
  const legacy = buildAgentConfig({ ping_mode: 'tcp', custom_ct: 'example.com:8443' }, null, 7);
  assert.equal(legacy.custom_ct, 'example.com:8443');
  assert.match(serializeAgentConfig(legacy), /&custom_ct=example.com:8443&/);
  const longHost = `${'a'.repeat(40)}.${'b'.repeat(40)}.example.com`;
  assert.equal(buildAgentConfig({ ping_mode: 'tcp', custom_ct: `https://${longHost}/health` }, null, 7).custom_ct, '');
  assert.equal(buildAgentConfig({ ping_mode: 'tcp', custom_ct: `https://${longHost}/health` }).custom_ct, `${longHost}:443`);
});

test('TCP 和 ICMP 模式从网址提取主机和端口', () => {
  for (const mode of ['tcp', 'icmp']) {
    const config = buildAgentConfig({ ping_mode: mode }, {
      custom_ct: 'https://example.com/ready',
      custom_cu: 'http://example.org:8080/check',
      custom_cm: 'https://[2001:db8::1]/check'
    });
    assert.equal(config.custom_ct, 'example.com:443');
    assert.equal(config.custom_cu, 'example.org:8080');
    assert.equal(config.custom_cm, '[2001:db8::1]:443');
  }
});

test('非 root 安装保留 HTTP 模式，仅将 ICMP 回退到 TCP', () => {
  assert.equal(normalizeInstallPingMode('http', true), 'http');
  assert.equal(normalizeInstallPingMode('icmp', true), 'tcp');
  assert.equal(normalizeInstallPingMode('icmp', false), 'icmp');
  assert.equal(normalizeInstallPingMode('tcp', true), 'tcp');
});

test('八个最大长度网址的配置仍在探针接收上限内', () => {
  const target = 'https://example.com/' + '!'.repeat(490);
  assert.equal(validatePingNode(target).valid, true);
  const fields = ['custom_ct', 'custom_cu', 'custom_cm', 'custom_bd', 'node_1', 'node_2', 'node_3', 'node_4'];
  const server = { ping_mode: 'http', ...Object.fromEntries(fields.map(field => [field, target])) };
  const body = serializeAgentConfig(buildAgentConfig(server));
  assert.ok(body.length < 16 * 1024);
  assert.ok(body.length > 1024);
});
