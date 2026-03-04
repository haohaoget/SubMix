// VLESS 协议解析器

import { BaseProtocolParser, ProxyNode, VlessConfig } from './base';

/**
 * VLESS 协议解析器
 */
export class VlessParser extends BaseProtocolParser {
  /**
   * 检查是否支持 VLESS 协议
   */
  supports(url: string): boolean {
    return url.startsWith('vless://');
  }

  /**
   * 获取支持的流控模式
   */
  public static getSupportedFlows(): string[] {
    return [
      '', // 无流控
      'xtls-rprx-vision', // XTLS RPRX Vision
      'xtls-rprx-vision-udp443' // XTLS RPRX Vision UDP443
    ];
  }

  /**
   * 获取支持的传输层协议
   */
  public static getSupportedNetworks(): string[] {
    return [
      'tcp', 'ws', 'http', 'h2', 'grpc'
    ];
  }

  /**
   * 获取支持的数据包编码
   */
  public static getSupportedPacketEncoding(): string[] {
    return [
      '', // 原始编码
      'packetaddr', // v2ray 5+ 支持
      'xudp' // xray 支持
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
   * 解析 VLESS 链接（基于 mihomo 官方文档）
   * vless://uuid@server:port?param1=value1&param2=value2#name
   */
  parse(url: string): ProxyNode | null {
    try {
      if (!this.supports(url)) {
        throw new Error('不是有效的 VLESS 链接');
      }

      const urlObj = new URL(url);
      const uuid = urlObj.username;
      const server = this.handleHostname(urlObj.hostname);
      const port = parseInt(urlObj.port) || 443;
      const name = decodeURIComponent(urlObj.hash.slice(1)) || `vless-${server}`;
      const params = this.parseUrlParams(urlObj.search);

      // 验证 UUID 格式
      if (!uuid || !this.isValidUUID(uuid)) {
        if (process.env.NODE_ENV === 'development') {
          console.warn('VLESS UUID 格式无效:', uuid);
        }
      }

      const config: ProxyNode & VlessConfig = {
        name,
        type: 'vless',
        server,
        port,
        uuid,
        udp: this.parseUdpParam(params.udp),
      };

      // 处理传输层协议 (network)
      const network = params.type || params.network || 'tcp';
      if (VlessParser.getSupportedNetworks().includes(network)) {
        config.network = network;
      } else {
        console.warn(`不支持的传输协议: ${network}，使用默认 tcp`);
        config.network = 'tcp';
      }

      // 处理流控 (flow)
      if (params.flow) {
        if (VlessParser.getSupportedFlows().includes(params.flow)) {
          config.flow = params.flow;
        } else {
          console.warn(`不支持的流控模式: ${params.flow}`);
        }
      }

      // 处理数据包编码 (packet-encoding)
      if (params['packet-encoding'] || params.packetEncoding) {
        const packetEncoding = params['packet-encoding'] || params.packetEncoding;
        if (VlessParser.getSupportedPacketEncoding().includes(packetEncoding)) {
          config['packet-encoding'] = packetEncoding;
        } else {
          console.warn(`不支持的数据包编码: ${packetEncoding}`);
        }
      }

      // 处理加密配置 (encryption)
      if (params.encryption) {
        config.encryption = params.encryption;
      } else {
        config.encryption = ''; // VLESS 默认无加密
      }

      // 处理 TLS 配置
      this.parseTLSConfig(config, params);

      // 处理传输层特定配置
      this.parseTransportConfig(config, params);

      // 处理 SMUX 多路复用
      if (params.smux || params['smux-enabled']) {
        config.smux = {
          enabled: this.parseBooleanParam(params.smux || params['smux-enabled'], false)
        };
      }

      return config;
    } catch (error) {
      console.error('解析 VLESS 链接失败:', error);
      return null;
    }
  }

  /**
   * 解析 TLS 相关配置
   */
  private parseTLSConfig(config: ProxyNode & VlessConfig, params: Record<string, string>): void {
    // 检查是否启用 TLS
    const security = params.security || params.tls;
    if (security === 'tls' || security === 'reality' || params.tls === 'true') {
      config.tls = true;

      // servername (SNI)
      if (params.sni || params.servername) {
        config.servername = params.sni || params.servername;
      }

      // ALPN 协议
      if (params.alpn) {
        const alpnList = params.alpn.split(',').map(a => a.trim()).filter(a => a);
        if (alpnList.length > 0) {
          config.alpn = alpnList;
        }
      }

      // 客户端指纹 (VLESS协议使用client-fingerprint字段)
      if (params['client-fingerprint'] || params.clientFingerprint || params.fingerprint || params.fp) {
        // 优先使用client-fingerprint，其次是fingerprint（兼容性处理）
        const clientFp = params['client-fingerprint'] || params.clientFingerprint || params.fingerprint || params.fp;
        if (VlessParser.getSupportedClientFingerprints().includes(clientFp)) {
          config['client-fingerprint'] = clientFp;
        } else {
          console.warn(`不支持的客户端指纹: ${clientFp}，支持的指纹: ${VlessParser.getSupportedClientFingerprints().join(', ')}`);
          // 设置默认值
          config['client-fingerprint'] = 'chrome';
        }
      }

      // 处理ECH配置 (ech)
      if (params.ech) {
        config['ech-opts'] = {};
        // 先 decode提取 "+" 前的部分
        const echValue = decodeURIComponent(params.ech.trim());
        let domain = echValue.split('+')[0]?.trim();
        // 如果 domain 里还有空格再按空格取第一个有效字段
        if (domain.includes(' ')) {
          domain = domain.split(/\s+/)[0].trim();
        }

        // 判断域名是否有效（非空且包含至少一个点）
        const hasValidDomain = domain && domain.includes('.');

        if (hasValidDomain) {
          config['ech-opts'].enable = true;
          config['ech-opts']['query-server-name'] = domain;
        } else {
          config['ech-opts'].enable = false;
        }
      }

      // 跳过证书验证
      if (params['skip-cert-verify'] || params.allowInsecure) {
        config['skip-cert-verify'] = this.parseBooleanParam(
          params['skip-cert-verify'] || params.allowInsecure
        );
      }

      // REALITY 配置
      if (security === 'reality' || params.reality) {
        config['reality-opts'] = {};

        if (params.pbk || params['public-key']) {
          config['reality-opts']['public-key'] = params.pbk || params['public-key'];
        }

        if (params.sid || params['short-id']) {
          config['reality-opts']['short-id'] = params.sid || params['short-id'];
        }

        if (!config['reality-opts']['public-key']) {
          console.warn('REALITY 配置缺少 public-key 参数');
        }
      }
    }
  }

  /**
   * 解析传输层特定配置
   */
  private parseTransportConfig(config: ProxyNode & VlessConfig, params: Record<string, string>): void {
    const network = config.network || 'tcp';

    switch (network) {
      case 'ws':
        this.parseWebSocketConfig(config, params);
        break;
      case 'http':
        this.parseHTTPConfig(config, params);
        break;
      case 'h2':
        this.parseHTTP2Config(config, params);
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
  private parseWebSocketConfig(config: ProxyNode & VlessConfig, params: Record<string, string>): void {
    config['ws-opts'] = {};

    if (params.path) {
      config['ws-opts'].path = params.path;
    }

    // WebSocket Headers
    if (params.host) {
      config['ws-opts'].headers = { host: params.host };
    }

    // 早期数据长度
    if (params['early-data-header-name'] || params.ed) {
      config['ws-opts']['early-data-header-name'] = params['early-data-header-name'] || params.ed;
    }
  }

  /**
   * 解析 HTTP 配置
   */
  private parseHTTPConfig(config: ProxyNode & VlessConfig, params: Record<string, string>): void {
    config['http-opts'] = {};

    if (params.path) {
      const paths = params.path.split(',').map(p => p.trim()).filter(p => p);
      config['http-opts'].path = paths;
    }

    if (params.host) {
      const hosts = params.host.split(',').map(h => h.trim()).filter(h => h);
      config['http-opts'].headers = { Host: hosts };
    }
  }

  /**
   * 解析 HTTP/2 配置
   */
  private parseHTTP2Config(config: ProxyNode & VlessConfig, params: Record<string, string>): void {
    config['h2-opts'] = {};

    if (params.path) {
      config['h2-opts'].path = params.path;
    }

    if (params.host) {
      const hosts = params.host.split(',').map(h => h.trim()).filter(h => h);
      config['h2-opts'].host = hosts;
    }
  }

  /**
   * 解析 gRPC 配置
   */
  private parseGRPCConfig(config: ProxyNode & VlessConfig, params: Record<string, string>): void {
    config['grpc-opts'] = {};

    if (params.serviceName || params['grpc-service-name']) {
      config['grpc-opts']['grpc-service-name'] = params.serviceName || params['grpc-service-name'];
    }

    if (params['grpc-mode']) {
      config['grpc-opts']['grpc-mode'] = params['grpc-mode'];
    }
  }

  /**
   * 验证 UUID 格式
   */
  private isValidUUID(uuid: string): boolean {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
  }
}
