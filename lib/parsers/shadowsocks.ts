// Shadowsocks 协议解析器

import { BaseProtocolParser, ProxyNode, ShadowsocksConfig } from './base';

/**
 * Shadowsocks 协议解析器
 */
export class ShadowsocksParser extends BaseProtocolParser {
  /**
   * 检查是否支持 Shadowsocks 协议
   */
  supports(url: string): boolean {
    return url.startsWith('ss://');
  }

  /**
   * 检测是否为SS2022加密方法
   */
  public static isSSR2022Cipher(cipher: string): boolean {
    if (!cipher) return false;
    return cipher.includes('2022');
  }

  /**
   * 检查是否为 SS2022 加密方法
   */
  private isSS2022Method(method: string): boolean {
    const ss2022Methods = [
      '2022-blake3-aes-128-gcm',
      '2022-blake3-aes-256-gcm',
      '2022-blake3-chacha20-poly1305'
    ];
    return ss2022Methods.includes(method.toLowerCase());
  }

  /**
   * 获取支持的 Shadowsocks 加密方法（基于 mihomo 官方文档）
   */
  public static getSupportedSSMethods(): string[] {
    return [
      // AES 系列
      'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
      'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
      'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
      'aes-128-ccm', 'aes-192-ccm', 'aes-256-ccm',
      'aes-128-gcm-siv', 'aes-256-gcm-siv',

      // CHACHA 系列
      'chacha20-ietf', 'chacha20', 'xchacha20',
      'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
      'chacha8-ietf-poly1305', 'xchacha8-ietf-poly1305',

      // 2022 Blake3 系列
      '2022-blake3-aes-128-gcm',
      '2022-blake3-aes-256-gcm',
      '2022-blake3-chacha20-poly1305',

      // LEA 系列
      'lea-128-gcm', 'lea-192-gcm', 'lea-256-gcm',

      // 其他
      'rabbit128-poly1305', 'aegis-128l', 'aegis-256',
      'aez-384', 'deoxys-ii-256-128', 'rc4-md5', 'none'
    ];
  }

  /**
   * 获取允许的插件名称列表
   */
  public static getAllowedPlugins(): string[] {
    return ['obfs', 'simple-obfs', 'obfs-local', 'v2ray-plugin', 'shadow-tls', 'restls', 'gost-plugin'];
  }

  /**
   * 解析插件选项参数
   * @param pluginOptsStr 插件选项字符串，格式：key=value;key2=value2
   * @param pluginName 插件名称，用于特定插件的参数适配
   */
  private parsePluginOpts(pluginOptsStr: string, pluginName: string): Record<string, string | number | boolean> {
    const pluginOpts: Record<string, string | number | boolean> = {};

    if (!pluginOptsStr) return pluginOpts;

    // 解析基本的键值对格式
    const opts = pluginOptsStr.split(';');

    for (const opt of opts) {
      const [key, value] = opt.split('=');
      if (key && value !== undefined) {
        const trimmedKey = key.trim();
        const trimmedValue = value.trim();

        // 根据插件类型和键名进行特定转换
        if (this.shouldConvertToBoolean(trimmedKey, pluginName)) {
          pluginOpts[trimmedKey] = trimmedValue.toLowerCase() === 'true';
        } else if (this.shouldConvertToNumber(trimmedKey, pluginName)) {
          const numValue = parseInt(trimmedValue);
          pluginOpts[trimmedKey] = isNaN(numValue) ? trimmedValue : numValue;
        } else {
          pluginOpts[trimmedKey] = trimmedValue;
        }
      }
    }

    return pluginOpts;
  }

  /**
   * 判断是否应该转换为布尔值
   */
  private shouldConvertToBoolean(key: string, pluginName: string): boolean {
    const generalBooleanKeys = ['tls', 'skip-cert-verify', 'allowInsecure', 'udp'];

    // 插件特定的布尔值参数
    const pluginSpecificBooleanKeys: Record<string, string[]> = {
      'v2ray-plugin': ['tls', 'skip-cert-verify'],
      'gost-plugin': ['tls', 'skip-cert-verify']
    };

    // 检查通用布尔值参数
    if (generalBooleanKeys.includes(key)) {
      return true;
    }

    // 检查插件特定的布尔值参数
    if (pluginName && pluginSpecificBooleanKeys[pluginName]) {
      return pluginSpecificBooleanKeys[pluginName].includes(key);
    }

    return false;
  }

  /**
   * 判断是否应该转换为数值
   */
  private shouldConvertToNumber(key: string, pluginName: string): boolean {
    const generalNumberKeys = ['port', 'mux'];

    // 插件特定的数值参数
    const pluginSpecificNumberKeys: Record<string, string[]> = {
      'shadow-tls': ['server-port', 'version'],
      'restls': ['server-port'],
      'gost-plugin': ['port']
    };

    // 检查通用数值参数
    if (generalNumberKeys.includes(key)) {
      return true;
    }

    // 检查插件特定的数值参数
    if (pluginName && pluginSpecificNumberKeys[pluginName]) {
      return pluginSpecificNumberKeys[pluginName].includes(key);
    }

    return false;
  }

  /**
   * 验证并标准化插件配置
   * @param config 当前节点配置
   * @param pluginName 插件名称
   * @param pluginOpts 插件选项
   */
  private validateAndNormalizePluginConfig(
    config: ProxyNode & ShadowsocksConfig,
    pluginName: string,
    pluginOpts: Record<string, string | number | boolean>
  ): void {
    if (pluginName === 'obfs' || pluginName === 'simple-obfs' || pluginName === 'obfs-local') {
      // obfs 相关插件标准化

      // 处理obfs参数 (obfs-local使用obfs而不是mode)
      if (pluginOpts.obfs) {
        const obfsMode = pluginOpts.obfs.toString().toLowerCase();
        if (!['http', 'tls'].includes(obfsMode)) {
          console.warn(`obfs 插件不支持的模式: ${obfsMode}，将使用默认模式 http`);
          pluginOpts.obfs = 'http';
        } else {
          pluginOpts.obfs = obfsMode;
        }
      } else if (pluginOpts.mode) {
        // 兼容mode参数
        const mode = pluginOpts.mode.toString().toLowerCase();
        if (!['http', 'tls'].includes(mode)) {
          console.warn(`obfs 插件不支持的模式: ${mode}，将使用默认模式 http`);
          pluginOpts.mode = 'http';
        } else {
          pluginOpts.mode = mode;
        }
      } else {
        // 根据插件名称设置默认参数
        if (pluginName === 'obfs-local') {
          pluginOpts.obfs = 'http';
        } else {
          pluginOpts.mode = 'http';
        }
      }

      // 处理host参数 (obfs-local使用obfs-host)
      const hostKey = pluginOpts['obfs-host'] ? 'obfs-host' : 'host';
      if (!pluginOpts[hostKey]) {
        console.warn(`${pluginName} 插件缺少 ${hostKey} 参数，建议设置混淆域名`);
      }

    } else if (pluginName === 'v2ray-plugin') {
      // v2ray-plugin 插件标准化（基于 mihomo 官方文档）
      if (pluginOpts.mode) {
        const mode = pluginOpts.mode.toString().toLowerCase();
        if (mode !== 'websocket') {
          console.warn(`v2ray-plugin 当前只支持 websocket 模式，收到: ${mode}`);
          pluginOpts.mode = 'websocket';
        } else {
          pluginOpts.mode = mode;
        }
      } else {
        pluginOpts.mode = 'websocket';
      }

      // 确保布尔值类型正确
      if (pluginOpts.tls !== undefined && typeof pluginOpts.tls !== 'boolean') {
        pluginOpts.tls = this.parseBooleanParam(pluginOpts.tls.toString());
      }

      if (pluginOpts['skip-cert-verify'] !== undefined && typeof pluginOpts['skip-cert-verify'] !== 'boolean') {
        pluginOpts['skip-cert-verify'] = this.parseBooleanParam(pluginOpts['skip-cert-verify'].toString());
      }

      if (pluginOpts.mux !== undefined && typeof pluginOpts.mux !== 'boolean') {
        pluginOpts.mux = this.parseBooleanParam(pluginOpts.mux.toString());
      }

      if (pluginOpts['v2ray-http-upgrade'] !== undefined && typeof pluginOpts['v2ray-http-upgrade'] !== 'boolean') {
        pluginOpts['v2ray-http-upgrade'] = this.parseBooleanParam(pluginOpts['v2ray-http-upgrade'].toString());
      }

      // 默认路径
      if (!pluginOpts.path) {
        pluginOpts.path = '/';
      }

      // 处理headers配置
      if (pluginOpts.headers && typeof pluginOpts.headers === 'string') {
        try {
          pluginOpts.headers = JSON.parse(pluginOpts.headers);
        } catch {
          console.warn('v2ray-plugin headers 格式错误，应为JSON格式');
          delete pluginOpts.headers;
        }
      }

    } else if (pluginName === 'shadow-tls') {
      // shadow-tls 插件标准化（基于 mihomo 官方文档）

      // 验证必需参数
      if (!pluginOpts.host && !pluginOpts.server) {
        console.warn('shadow-tls 插件缺少 host 参数');
      }

      if (!pluginOpts.password) {
        console.warn('shadow-tls 插件缺少 password 参数');
      }

      // 设置默认版本
      if (!pluginOpts.version) {
        pluginOpts.version = 2; // shadow-tls v2 默认
      } else {
        pluginOpts.version = this.parseNumberParam(pluginOpts.version.toString(), 2);
      }

      // 兼容性处理：server -> host
      if (pluginOpts.server && !pluginOpts.host) {
        pluginOpts.host = pluginOpts.server;
        delete pluginOpts.server;
      }

    } else if (pluginName === 'restls') {
      // restls 插件标准化（基于 mihomo 官方文档）

      // 验证必需参数
      if (!pluginOpts.host && !pluginOpts.server) {
        console.warn('restls 插件缺少 host 参数');
      }

      if (!pluginOpts.password) {
        console.warn('restls 插件缺少 password 参数');
      }

      // 设置默认版本提示
      if (!pluginOpts['version-hint']) {
        pluginOpts['version-hint'] = 'tls13';
      }

      // 兼容性处理：server -> host
      if (pluginOpts.server && !pluginOpts.host) {
        pluginOpts.host = pluginOpts.server;
        delete pluginOpts.server;
      }

    } else if (pluginName === 'gost-plugin') {
      // gost-plugin 插件标准化（基于 mihomo 官方文档）

      // 设置默认模式
      if (!pluginOpts.mode) {
        pluginOpts.mode = 'websocket'; // 默认使用WebSocket模式
      } else {
        const mode = pluginOpts.mode.toString().toLowerCase();
        if (!['websocket', 'tls'].includes(mode)) {
          console.warn(`gost-plugin 不支持的模式: ${mode}，将使用默认模式 websocket`);
          pluginOpts.mode = 'websocket';
        } else {
          pluginOpts.mode = mode;
        }
      }

      // 确保布尔值类型正确
      if (pluginOpts.tls !== undefined && typeof pluginOpts.tls !== 'boolean') {
        pluginOpts.tls = this.parseBooleanParam(pluginOpts.tls.toString());
      }

      if (pluginOpts['skip-cert-verify'] !== undefined && typeof pluginOpts['skip-cert-verify'] !== 'boolean') {
        pluginOpts['skip-cert-verify'] = this.parseBooleanParam(pluginOpts['skip-cert-verify'].toString());
      }

      if (pluginOpts.mux !== undefined && typeof pluginOpts.mux !== 'boolean') {
        pluginOpts.mux = this.parseBooleanParam(pluginOpts.mux.toString());
      }

      // 默认路径
      if (!pluginOpts.path) {
        pluginOpts.path = '/';
      }

      // 处理headers配置
      if (pluginOpts.headers && typeof pluginOpts.headers === 'string') {
        try {
          pluginOpts.headers = JSON.parse(pluginOpts.headers);
        } catch {
          console.warn('gost-plugin headers 格式错误，应为JSON格式');
          delete pluginOpts.headers;
        }
      }

    } else {
      // 检查是否为允许的插件但未实现特定处理
      if (ShadowsocksParser.getAllowedPlugins().includes(pluginName)) {
        console.info(`插件 ${pluginName} 将使用通用参数解析`);
      } else {
        console.warn(`插件 ${pluginName} 不在允许的插件列表中`);
      }
    }
  }

  /**
   * 插件名称映射 - 将实际插件名称映射为标准名称
   */
  private mapPluginName(pluginName: string): string {
    const pluginMapping: Record<string, string> = {
      'obfs-local': 'obfs',
      'simple-obfs': 'obfs'
    };

    return pluginMapping[pluginName] || pluginName;
  }

  /**
   * 插件参数映射 - 将插件特定参数映射为标准参数
   */
  private mapPluginOptions(pluginName: string, options: Record<string, string | number | boolean>): Record<string, string | number | boolean> {
    const mappedOptions: Record<string, string | number | boolean> = {};

    // obfs-local 和 simple-obfs 的参数映射
    if (pluginName === 'obfs-local' || pluginName === 'simple-obfs') {
      for (const [key, value] of Object.entries(options)) {
        switch (key) {
          case 'obfs':
            mappedOptions.mode = value;
            break;
          case 'obfs-host':
            mappedOptions.host = value;
            break;
          default:
            mappedOptions[key] = value;
        }
      }
    } else {
      // 其他插件保持原样
      Object.assign(mappedOptions, options);
    }

    return mappedOptions;
  }

  /**
   * 解析 Shadowsocks 链接 (支持 SS 和 SS2022)
   * ss://method:password@server:port#name
   * ss://base64(method:password)@server:port#name
   */
  parse(url: string): ProxyNode | null {
    try {
      if (!this.supports(url)) {
        throw new Error('不是有效的 Shadowsocks 链接');
      }

      const urlObj = new URL(url);
      let method: string;
      let password: string;

      // 处理两种编码格式
      if (urlObj.username && urlObj.password) {
        // 格式：ss://method:password@server:port#name
        method = decodeURIComponent(urlObj.username);
        password = decodeURIComponent(urlObj.password);
      } else {
        // 格式：ss://base64(method:password)@server:port#name
        try {
          // 提取 Base64 编码部分
          const urlWithoutProtocol = url.slice(5); // 移除 "ss://"
          const atIndex = urlWithoutProtocol.indexOf('@');

          if (atIndex === -1) {
            throw new Error('无效的 Shadowsocks 链接格式');
          }

          const encoded = urlWithoutProtocol.slice(0, atIndex);
          const decoded = this.decodeBase64(encoded);

          const colonIndex = decoded.indexOf(':');
          if (colonIndex === -1) {
            throw new Error('Base64 解码后格式无效');
          }

          method = decoded.slice(0, colonIndex);
          password = decoded.slice(colonIndex + 1);
        } catch (error) {
          console.error('Base64 格式解析失败:', error);
          throw new Error('无法解析 Base64 编码的 Shadowsocks 链接');
        }
      }

      const server = this.handleHostname(urlObj.hostname);
      const port = parseInt(urlObj.port) || 8388;
      const name = decodeURIComponent(urlObj.hash.slice(1)) || `ss-${server}`;
      const params = this.parseUrlParams(urlObj.search);

      // 验证加密方法
      const supportedMethods = ShadowsocksParser.getSupportedSSMethods();
      if (!supportedMethods.includes(method.toLowerCase())) {
        console.warn(`不支持的 Shadowsocks 加密方法: ${method}`);
      }

      // 根据加密方法确定协议类型
      const isSSR2022 = this.isSS2022Method(method);

      const config: ProxyNode & ShadowsocksConfig = {
        name,
        type: 'ss', // SS2022 是 SS 协议的分支，统一使用 'ss' 类型
        server,
        port,
        cipher: method,
        password,
        // UDP支持根据URL参数设置，默认为true
        udp: this.parseUdpParam(params.udp),
        // 新增的 mihomo 配置字段
        'udp-over-tcp': this.parseBooleanParam(params['udp-over-tcp'], false),
        'udp-over-tcp-version': this.parseNumberParam(params['udp-over-tcp-version'], 2),
        'ip-version': params['ip-version'] === 'ipv6' ? 'ipv6' : 'ipv4',
      };

      // 处理 smux 多路复用配置
      if (params.smux || params['smux-enabled']) {
        config.smux = {
          enabled: this.parseBooleanParam(params.smux || params['smux-enabled'], false)
        };
      }

      // 处理混淆插件参数
      if (params.plugin) {
        // 检查plugin参数是否包含配置信息（格式：plugin-name;key1=value1;key2=value2）
        const pluginParts = params.plugin.split(';');
        const originalPluginName = pluginParts[0];

        // 验证插件是否被允许
        if (!ShadowsocksParser.getAllowedPlugins().includes(originalPluginName)) {
          console.warn(`不支持的插件: ${originalPluginName}，允许的插件: ${ShadowsocksParser.getAllowedPlugins().join(', ')}`);
          return config; // 跳过不支持的插件
        }

        // 映射插件名称（如 obfs-local -> obfs）
        const mappedPluginName = this.mapPluginName(originalPluginName);
        config.plugin = mappedPluginName;

        let pluginOpts: Record<string, string | number | boolean> = {};

        // 处理plugin参数中的内联配置
        if (pluginParts.length > 1) {
          // 从plugin参数中解析配置选项
          const inlineOptsStr = pluginParts.slice(1).join(';');
          pluginOpts = this.parsePluginOpts(inlineOptsStr, originalPluginName);
        }

        // 处理独立的plugin-opts参数
        if (params['plugin-opts']) {
          const separateOpts = this.parsePluginOpts(params['plugin-opts'], originalPluginName);
          // 合并两种配置，独立的plugin-opts优先级更高
          pluginOpts = { ...pluginOpts, ...separateOpts };
        }

        // 映射插件参数（如 obfs -> mode, obfs-host -> host）
        const mappedPluginOpts = this.mapPluginOptions(originalPluginName, pluginOpts);

        // 验证并标准化插件配置（使用映射后的插件名称）
        this.validateAndNormalizePluginConfig(config, mappedPluginName, mappedPluginOpts);

        // 只有当有配置选项时才添加plugin-opts字段
        if (Object.keys(mappedPluginOpts).length > 0) {
          config['plugin-opts'] = mappedPluginOpts;
        }
      }

      // 处理 client-fingerprint 字段（shadow-tls 和 restls 插件需要）
      if (params['client-fingerprint']) {
        const fingerprint = params['client-fingerprint'];
        const validFingerprints = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random'];
        if (validFingerprints.includes(fingerprint.toLowerCase())) {
          config['client-fingerprint'] = fingerprint.toLowerCase();
        } else {
          console.warn(`不支持的客户端指纹: ${fingerprint}，支持的指纹: ${validFingerprints.join(', ')}`);
          config['client-fingerprint'] = 'chrome'; // 默认使用chrome指纹
        }
      }

      // 处理 SS2022 特殊配置
      if (isSSR2022) {
        // SS2022 协议的特殊处理
        config['server-port'] = port;

        // SS2022 密码格式验证
        if (!password || password.length < 16) {
          console.warn('SS2022 密码长度可能不足，建议使用更长的密码');
        }
      }

      return config;
    } catch (error) {
      console.error('解析 Shadowsocks 链接失败:', error);
      return null;
    }
  }
}
