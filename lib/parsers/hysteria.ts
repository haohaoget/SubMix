// Hysteria 协议解析器

import { BaseProtocolParser, ProxyNode, HysteriaConfig } from './base';

/**
 * Hysteria 协议解析器
 */
export class HysteriaParser extends BaseProtocolParser {
  /**
   * 检查是否支持 Hysteria 协议
   */
  supports(url: string): boolean {
    return url.startsWith('hysteria://') || url.startsWith('hy://');
  }

  /**
   * 获取支持的协议类型
   */
  public static getSupportedProtocols(): string[] {
    return [
      'udp',          // UDP 协议
      'wechat-video', // 微信视频通话伪装
      'faketcp'       // 伪 TCP 协议
    ];
  }

  /**
   * 获取支持的混淆类型
   */
  public static getSupportedObfs(): string[] {
    return [
      '', // 无混淆
      'simple', // 简单混淆
      'tls1.2_ticket_auth', // TLS 1.2 混淆
      'http_simple', // HTTP 简单混淆
      'http_post', // HTTP POST 混淆
      'random_head', // 随机头混淆
      'tls1.2_ticket_fastauth' // TLS 1.2 快速认证混淆
    ];
  }

  /**
   * 解析 Hysteria 链接（基于 mihomo 官方文档）
   * hysteria://auth-str@server:port?param1=value1&param2=value2#name
   */
  parse(url: string): ProxyNode | null {
    try {
      if (!this.supports(url)) {
        throw new Error('不是有效的 Hysteria 链接');
      }

      const urlObj = new URL(url);
      const authStr = urlObj.username;
      const server = this.handleHostname(urlObj.hostname);
      const port = parseInt(urlObj.port) || 443;
      const name = decodeURIComponent(urlObj.hash.slice(1)) || `hysteria-${server}`;
      const params = this.parseUrlParams(urlObj.search);

      // 验证认证字符串
      if (!authStr) {
        console.warn('Hysteria 认证字符串为空');
      }

      const config: ProxyNode & HysteriaConfig = {
        name,
        type: 'hysteria',
        server,
        port,
        'auth-str': authStr,
        udp: this.parseUdpParam(params.udp),
      };

      // 处理协议类型 (protocol)
      if (params.protocol) {
        if (HysteriaParser.getSupportedProtocols().includes(params.protocol)) {
          config.protocol = params.protocol;
        } else {
          console.warn(`不支持的协议类型: ${params.protocol}，使用默认 udp`);
          config.protocol = 'udp';
        }
      } else {
        config.protocol = 'udp'; // 默认 UDP
      }

      // 处理混淆 (obfs)
      if (params.obfs) {
        config.obfs = params.obfs;
      }

      // 处理带宽控制
      if (params.up) {
        config.up = this.parseBandwidth(params.up);
      }
      if (params.down) {
        config.down = this.parseBandwidth(params.down);
      }

      // 处理 TLS 相关配置
      this.parseTLSConfig(config, params);

      // 处理接收窗口配置
      this.parseWindowConfig(config, params);

      // 处理证书配置
      this.parseCertConfig(config, params);

      // 处理其他高级配置
      this.parseAdvancedConfig(config, params);

      return config;
    } catch (error) {
      console.error('解析 Hysteria 链接失败:', error);
      return null;
    }
  }

  /**
   * 解析带宽配置，支持单位
   */
  private parseBandwidth(bandwidth: string): string {
    if (!bandwidth) return '';

    // 如果已经包含单位，直接返回
    if (/\s*(Mbps|mbps|Kbps|kbps|Gbps|gbps|bps)$/i.test(bandwidth)) {
      return bandwidth;
    }

    // 如果只是数字，默认添加 Mbps 单位
    if (/^\d+$/.test(bandwidth)) {
      return `${bandwidth} Mbps`;
    }

    return bandwidth;
  }

  /**
   * 解析 TLS 相关配置
   */
  private parseTLSConfig(config: ProxyNode & HysteriaConfig, params: Record<string, string>): void {
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
    }

    // 指纹配置
    if (params.fingerprint) {
      config.fingerprint = params.fingerprint;
    }
  }

  /**
   * 解析接收窗口配置
   */
  private parseWindowConfig(config: ProxyNode & HysteriaConfig, params: Record<string, string>): void {
    // 连接接收窗口
    if (params['recv-window-conn'] || params.recvWindowConn) {
      const value = this.parseNumberParam(
        params['recv-window-conn'] || params.recvWindowConn
      );
      if (value !== undefined) {
        config['recv-window-conn'] = value;
      }
    }

    // 全局接收窗口
    if (params['recv-window'] || params.recvWindow) {
      const value = this.parseNumberParam(
        params['recv-window'] || params.recvWindow
      );
      if (value !== undefined) {
        config['recv-window'] = value;
      }
    }
  }

  /**
   * 解析证书配置
   */
  private parseCertConfig(config: ProxyNode & HysteriaConfig, params: Record<string, string>): void {
    // CA 证书文件路径
    if (params.ca) {
      config.ca = params.ca;
    }

    // CA 证书字符串
    if (params['ca-str'] || params.caStr) {
      config['ca-str'] = params['ca-str'] || params.caStr;
    }
  }

  /**
   * 解析其他高级配置
   */
  private parseAdvancedConfig(config: ProxyNode & HysteriaConfig, params: Record<string, string>): void {
    // 禁用 MTU 发现
    if (params['disable_mtu_discovery'] || params.disableMtuDiscovery) {
      config['disable_mtu_discovery'] = this.parseBooleanParam(
        params['disable_mtu_discovery'] || params.disableMtuDiscovery
      );
    }

    // 快速打开
    if (params['fast-open'] || params.fastOpen) {
      config['fast-open'] = this.parseBooleanParam(
        params['fast-open'] || params.fastOpen
      );
    }
  }
}
