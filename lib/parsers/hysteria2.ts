// Hysteria2 协议解析器

import { BaseProtocolParser, ProxyNode, Hysteria2Config } from './base';

/**
 * Hysteria2 协议解析器
 */
export class Hysteria2Parser extends BaseProtocolParser {
  /**
   * 检查是否支持 Hysteria2 协议
   */
  supports(url: string): boolean {
    return url.startsWith('hysteria2://') || url.startsWith('hy2://');
  }

  /**
   * 获取支持的混淆类型
   */
  public static getSupportedObfs(): string[] {
    return [
      '', // 无混淆
      'salamander' // 目前仅支持 salamander
    ];
  }

  /**
   * 解析 Hysteria2 链接（基于 mihomo 官方文档）
   * hysteria2://password@server:port?param1=value1&param2=value2#name
   */
  parse(url: string): ProxyNode | null {
    try {
      if (!this.supports(url)) {
        throw new Error('不是有效的 Hysteria2 链接');
      }

      const urlObj = new URL(url);
      const password = urlObj.username;
      const server = this.handleHostname(urlObj.hostname);
      const port = parseInt(urlObj.port) || 443;
      const name = decodeURIComponent(urlObj.hash.slice(1)) || `hysteria2-${server}`;
      const params = this.parseUrlParams(urlObj.search);

      // 验证密码
      if (!password) {
        console.warn('Hysteria2 认证密码为空');
      }

      const config: ProxyNode & Hysteria2Config = {
        name,
        type: 'hysteria2',
        server,
        port,
        password,
        udp: this.parseUdpParam(params.udp),
      };

      // 处理端口跳跃 (ports)
      if (params.ports) {
        config.ports = params.ports;
        // 如果配置了端口跳跃，会忽略单独的 port 配置
        console.info('启用端口跳跃，忽略单独的 port 配置');
      }

      // 处理混淆配置
      this.parseObfsConfig(config, params);

      // 处理 TLS 相关配置
      this.parseTLSConfig(config, params);

      // 处理带宽控制 (brutal 速率控制)
      this.parseBandwidthConfig(config, params);

      // 处理证书配置
      this.parseCertConfig(config, params);

      // 处理 QUIC-GO 特殊配置
      this.parseQuicGoConfig(config, params);

      return config;
    } catch (error) {
      console.error('解析 Hysteria2 链接失败:', error);
      return null;
    }
  }

  /**
   * 解析混淆配置
   */
  private parseObfsConfig(config: ProxyNode & Hysteria2Config, params: Record<string, string>): void {
    // QUIC 流量混淆器类型
    if (params.obfs) {
      if (Hysteria2Parser.getSupportedObfs().includes(params.obfs)) {
        config.obfs = params.obfs;

        // 混淆器密码
        if (params['obfs-password'] || params.obfsPassword) {
          config['obfs-password'] = params['obfs-password'] || params.obfsPassword;
        }
      } else {
        console.warn(`不支持的混淆类型: ${params.obfs}，目前仅支持 salamander`);
      }
    }
  }

  /**
   * 解析 TLS 相关配置
   */
  private parseTLSConfig(config: ProxyNode & Hysteria2Config, params: Record<string, string>): void {
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

    // 指纹配置
    if (params.fingerprint) {
      config.fingerprint = params.fingerprint;
    }

    // ALPN 协议
    if (params.alpn) {
      const alpnList = params.alpn.split(',').map(a => a.trim()).filter(a => a);
      if (alpnList.length > 0) {
        config.alpn = alpnList;
      }
    }
  }

  /**
   * 解析带宽控制配置 (brutal 速率控制)
   */
  private parseBandwidthConfig(config: ProxyNode & Hysteria2Config, params: Record<string, string>): void {
    // 上传带宽
    if (params.up) {
      config.up = this.parseBandwidth(params.up);
    }

    // 下载带宽
    if (params.down) {
      config.down = this.parseBandwidth(params.down);
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
   * 解析证书配置
   */
  private parseCertConfig(config: ProxyNode & Hysteria2Config, params: Record<string, string>): void {
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
   * 解析 QUIC-GO 特殊配置项
   * 注意：这些是高级配置，不要随意修改除非你知道你在干什么
   */
  private parseQuicGoConfig(config: ProxyNode & Hysteria2Config, params: Record<string, string>): void {
    // 初始流接收窗口
    if (params['initial-stream-receive-window'] || params.initialStreamReceiveWindow) {
      const value = this.parseNumberParam(
        params['initial-stream-receive-window'] || params.initialStreamReceiveWindow
      );
      if (value !== undefined) {
        config['initial-stream-receive-window'] = value;
      }
    }

    // 最大流接收窗口
    if (params['max-stream-receive-window'] || params.maxStreamReceiveWindow) {
      const value = this.parseNumberParam(
        params['max-stream-receive-window'] || params.maxStreamReceiveWindow
      );
      if (value !== undefined) {
        config['max-stream-receive-window'] = value;
      }
    }

    // 初始连接接收窗口
    if (params['initial-connection-receive-window'] || params.initialConnectionReceiveWindow) {
      const value = this.parseNumberParam(
        params['initial-connection-receive-window'] || params.initialConnectionReceiveWindow
      );
      if (value !== undefined) {
        config['initial-connection-receive-window'] = value;
      }
    }

    // 最大连接接收窗口
    if (params['max-connection-receive-window'] || params.maxConnectionReceiveWindow) {
      const value = this.parseNumberParam(
        params['max-connection-receive-window'] || params.maxConnectionReceiveWindow
      );
      if (value !== undefined) {
        config['max-connection-receive-window'] = value;
      }
    }
  }
}

