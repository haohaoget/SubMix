// Trojan 协议解析器

import { BaseProtocolParser, ProxyNode, TrojanConfig } from './base';

/**
 * Trojan 协议解析器
 */
export class TrojanParser extends BaseProtocolParser {
  /**
   * 检查是否支持 Trojan 协议
   */
  supports(url: string): boolean {
    return url.startsWith('trojan://');
  }

  /**
   * 获取支持的传输层协议
   */
  public static getSupportedNetworks(): string[] {
    return [
      'tcp',   // TCP 传输（默认）
      'ws',    // WebSocket 传输
      'grpc'   // gRPC 传输
    ];
  }

  /**
   * 获取支持的客户端指纹
   */
  public static getSupportedClientFingerprints(): string[] {
    return [
      'chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random'
    ];
  }

  /**
   * 获取支持的 Shadowsocks 加密方法（trojan-go）
   */
  public static getSupportedSSMethods(): string[] {
    return [
      'aes-128-gcm',
      'aes-256-gcm',
      'chacha20-ietf-poly1305'
    ];
  }

  /**
   * 解析 Trojan 链接（基于 mihomo 官方文档）
   * trojan://password@server:port?param1=value1&param2=value2#name
   */
  parse(url: string): ProxyNode | null {
    try {
      if (!this.supports(url)) {
        throw new Error('不是有效的 Trojan 链接');
      }

      const urlObj = new URL(url);
      const password = urlObj.username;
      const server = urlObj.hostname;
      const port = parseInt(urlObj.port) || 443;
      const name = decodeURIComponent(urlObj.hash.slice(1)) || `trojan-${server}`;
      const params = this.parseUrlParams(urlObj.search);

      // 验证密码
      if (!password) {
        console.warn('Trojan 服务器密码为空');
      }

      const config: ProxyNode & TrojanConfig = {
        name,
        type: 'trojan',
        server,
        port,
        password,
        udp: this.parseUdpParam(params.udp),
        id: this.generateId(),
      };

      // 处理传输层协议
      this.parseNetworkConfig(config, params);

      // 处理 TLS 配置
      this.parseTLSConfig(config, params);

      // 处理 REALITY 配置
      this.parseRealityConfig(config, params);

      // 处理 Shadowsocks AEAD 加密（trojan-go）
      this.parseSSOptsConfig(config, params);

      // 处理 SMUX 多路复用
      this.parseSMUXConfig(config, params);

      return config;
    } catch (error) {
      console.error('解析 Trojan 链接失败:', error);
      return null;
    }
  }

  /**
   * 解析传输层协议配置
   */
  private parseNetworkConfig(config: ProxyNode & TrojanConfig, params: Record<string, string>): void {
    // 处理传输层协议
    const network = params.type || params.network || 'tcp';
    if (TrojanParser.getSupportedNetworks().includes(network)) {
      config.network = network;
    } else {
      console.warn(`不支持的传输协议: ${network}，使用默认 tcp`);
      config.network = 'tcp';
    }

    // 根据传输层协议设置特定配置
    switch (config.network) {
      case 'ws':
        this.parseWebSocketConfig(config, params);
        break;
      case 'grpc':
        this.parseGRPCConfig(config, params);
        break;
      case 'tcp':
      default:
        // TCP 无需额外配置
        break;
    }
  }

  /**
   * 解析 WebSocket 配置
   */
  private parseWebSocketConfig(config: ProxyNode & TrojanConfig, params: Record<string, string>): void {
    config['ws-opts'] = {};

    if (params.path) {
      config['ws-opts'].path = params.path;
    }

    if (params.host) {
      config['ws-opts'].headers = { host: params.host };
    }
  }

  /**
   * 解析 gRPC 配置
   */
  private parseGRPCConfig(config: ProxyNode & TrojanConfig, params: Record<string, string>): void {
    config['grpc-opts'] = {};

    if (params.serviceName || params['grpc-service-name']) {
      config['grpc-opts']['grpc-service-name'] = params.serviceName || params['grpc-service-name'];
    }
  }

  /**
   * 解析 TLS 相关配置
   */
  private parseTLSConfig(config: ProxyNode & TrojanConfig, params: Record<string, string>): void {
    // SNI 配置
    if (params.sni) {
      config.sni = params.sni;
    }

    // 跳过证书验证
    if (params['skip-cert-verify'] || params.allowInsecure) {
      config['skip-cert-verify'] = this.parseBooleanParam(
        params['skip-cert-verify'] || params.allowInsecure
      );
    }

    // ALPN 协议
    if (params.alpn) {
      const alpnList = params.alpn.split(',').map(a => a.trim()).filter(a => a);
      if (alpnList.length > 0) {
        config.alpn = alpnList;
      }
    } else {
      // 设置默认 ALPN
      config.alpn = ['h2', 'http/1.1'];
    }

    // 服务器指纹
    if (params.fingerprint) {
      config.fingerprint = params.fingerprint;
    }

    // 客户端指纹
    if (params['client-fingerprint'] || params.clientFingerprint) {
      const clientFp = params['client-fingerprint'] || params.clientFingerprint;
      if (TrojanParser.getSupportedClientFingerprints().includes(clientFp)) {
        config['client-fingerprint'] = clientFp;
      } else {
        console.warn(`不支持的客户端指纹: ${clientFp}`);
      }
    }

    // 处理ECH配置 (ech)
    if (params.ech) {
      config['ech-opts'] = {};

      // 先 decode提取 "+" 前的部分
      const echValue = decodeURIComponent(params.ech.trim());
      const domain = echValue.split('+')[0]?.trim();

      // 判断域名是否有效（非空且包含至少一个点）
      const hasValidDomain = domain && domain.includes('.');

      if (hasValidDomain) {
        config['ech-opts'].enable = true;
        config['ech-opts']['query-server-name'] = domain;
      } else {
        config['ech-opts'].enable = false;
      }
    }
  }

  /**
   * 解析 REALITY 配置
   */
  private parseRealityConfig(config: ProxyNode & TrojanConfig, params: Record<string, string>): void {
    // 检查是否有 REALITY 相关配置
    if (params.pbk || params['public-key'] || params.sid || params['short-id']) {
      config['reality-opts'] = {};

      // REALITY 公钥
      if (params.pbk || params['public-key']) {
        config['reality-opts']['public-key'] = params.pbk || params['public-key'];
      }

      // REALITY 短 ID
      if (params.sid || params['short-id']) {
        config['reality-opts']['short-id'] = params.sid || params['short-id'];
      }

      if (!config['reality-opts']['public-key']) {
        console.warn('REALITY 配置缺少 public-key 参数');
      }
    }
  }

  /**
   * 解析 Shadowsocks AEAD 加密配置（trojan-go）
   */
  private parseSSOptsConfig(config: ProxyNode & TrojanConfig, params: Record<string, string>): void {
    // 检查是否启用 SS AEAD 加密
    if (params['ss-enabled'] || params.ssEnabled) {
      config['ss-opts'] = {
        enabled: this.parseBooleanParam(params['ss-enabled'] || params.ssEnabled, false)
      };

      // SS 加密方法
      if (params['ss-method'] || params.ssMethod) {
        const method = params['ss-method'] || params.ssMethod;
        if (TrojanParser.getSupportedSSMethods().includes(method)) {
          config['ss-opts'].method = method;
        } else {
          console.warn(`不支持的 SS 加密方法: ${method}`);
          config['ss-opts'].method = 'aes-128-gcm'; // 默认方法
        }
      } else {
        config['ss-opts'].method = 'aes-128-gcm'; // 默认方法
      }

      // SS 密码
      if (params['ss-password'] || params.ssPassword) {
        config['ss-opts'].password = params['ss-password'] || params.ssPassword;
      }
    }
  }

  /**
   * 解析 SMUX 多路复用配置
   */
  private parseSMUXConfig(config: ProxyNode & TrojanConfig, params: Record<string, string>): void {
    if (params.smux || params['smux-enabled']) {
      config.smux = {
        enabled: this.parseBooleanParam(params.smux || params['smux-enabled'], false)
      };
    }
  }
}

