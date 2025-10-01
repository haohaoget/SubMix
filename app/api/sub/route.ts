import { NextRequest, NextResponse } from 'next/server';
import { ProxyParser } from '@/lib/proxy-parser';
import { MihomoConfigGenerator } from '@/lib/mihomo-config';

/**
 * Sub API 端点
 * 支持格式: /api/sub?target=mihomo&url=${encodeURIComponent(request.url)}&insert=false&config=${encodeURIComponent(subconfig)}
 * 
 * 参数说明:
 * - target: 固定为 mihomo
 * - url: 经过URL编码的节点链接（多个节点以"|"分割），支持 VLESS、Hysteria、Hysteria2、Shadowsocks、Trojan 等协议
 * - insert: 是否插入额外配置（暂未实现）
 * - config: 经过URL编码的配置参数（可选）
 */

export async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url);
    const searchParams = url.searchParams;
    
    // 获取查询参数
    const target = searchParams.get('target');
    const encodedUrl = searchParams.get('url');
    // const insert = searchParams.get('insert'); // 暂未实现
    const encodedConfig = searchParams.get('config');
    
    // 验证必需参数
    if (!target) {
      return NextResponse.json(
        { error: '缺少 target 参数' },
        { status: 400 }
      );
    }
    
    if (!encodedUrl) {
      return NextResponse.json(
        { error: '缺少 url 参数' },
        { status: 400 }
      );
    }
    
    // 验证 target 参数
    if (target !== 'mihomo' && target !== 'clash') {
      return NextResponse.json(
        { error: `不支持的 target 类型: ${target}，目前仅支持 mihomo 和 clash` },
        { status: 400 }
      );
    }
    
    // 解码 URL 参数
    let decodedUrl: string;
    try {
      decodedUrl = decodeURIComponent(encodedUrl);
    } catch {
      return NextResponse.json(
        { error: 'url 参数解码失败' },
        { status: 400 }
      );
    }
    
    // 解析多个节点链接（以"|"分割）
    const nodeLinks = decodedUrl.split('|').map(url => url.trim()).filter(url => url.length > 0);
    
    if (nodeLinks.length === 0) {
      return NextResponse.json(
        { error: '没有找到有效的节点链接' },
        { status: 400 }
      );
    }
    
    // 解码配置参数（可选）
    let configOptions: Record<string, unknown> = {};
    if (encodedConfig) {
      try {
        const decodedConfig = decodeURIComponent(encodedConfig);
        // 尝试解析为JSON，如果失败则作为字符串处理
        try {
          configOptions = JSON.parse(decodedConfig);
        } catch {
          // 如果不是JSON格式，可以作为简单的键值对处理
          configOptions = { raw: decodedConfig };
        }
      } catch (error) {
        console.warn('config 参数解码失败，使用默认配置:', error);
      }
    }
    
    console.log(`接收到 ${nodeLinks.length} 个节点链接`);
    
    // 直接解析节点链接
    const proxies = ProxyParser.parseMultipleProxies(nodeLinks);
    
    if (proxies.length === 0) {
      return NextResponse.json(
        { error: '没有成功解析到任何有效的代理节点，请检查链接格式是否正确' },
        { status: 400 }
      );
    }
    
    console.log(`成功解析 ${proxies.length} 个代理节点`);
    
    // 根据配置选项生成配置
    let config;
    const ruleMode = (configOptions.ruleMode as 'whitelist' | 'blacklist') || 'whitelist';
    const configType = (configOptions.configType as 'simple' | 'full') || 'simple';
    
    if (configType === 'full') {
      config = MihomoConfigGenerator.generateConfig(proxies, ruleMode);
    } else {
      config = MihomoConfigGenerator.generateSimpleConfig(proxies, ruleMode);
    }
    
    // 转换为 YAML
    const yaml = MihomoConfigGenerator.configToYaml(config);
    
    // 返回 YAML 内容，设置正确的 Content-Type
    return new NextResponse(yaml, {
      status: 200,
      headers: {
        'Content-Type': 'text/yaml; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET',
        'Access-Control-Allow-Headers': 'Content-Type',
        'X-Proxy-Count': proxies.length.toString(),
        'X-Node-Count': nodeLinks.length.toString()
      }
    });
    
  } catch (error) {
    console.error('Sub API 处理失败:', error);
    
    return NextResponse.json(
      { 
        error: error instanceof Error ? error.message : '服务器内部错误',
        details: process.env.NODE_ENV === 'development' ? String(error) : undefined
      },
      { status: 500 }
    );
  }
}

// 支持 POST 方法（用于处理大量数据或复杂配置）
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { target, url, insert = false, config } = body;
    
    // 验证必需参数
    if (!target) {
      return NextResponse.json(
        { error: '缺少 target 参数' },
        { status: 400 }
      );
    }
    
    if (!url) {
      return NextResponse.json(
        { error: '缺少 url 参数' },
        { status: 400 }
      );
    }
    
    // 验证 target 参数
    if (target !== 'mihomo' && target !== 'clash') {
      return NextResponse.json(
        { error: `不支持的 target 类型: ${target}，目前仅支持 mihomo 和 clash` },
        { status: 400 }
      );
    }
    
    // 构造查询参数并重定向到 GET 处理
    const params = new URLSearchParams({
      target,
      url: Array.isArray(url) ? url.join('|') : url,
      insert: insert.toString()
    });
    
    if (config) {
      params.append('config', typeof config === 'string' ? config : JSON.stringify(config));
    }
    
    // 调用 GET 方法处理
    const newRequest = new Request(`${request.url}/?${params.toString()}`, {
      method: 'GET',
      headers: request.headers
    });
    
    return GET(newRequest as NextRequest);
    
  } catch (error) {
    console.error('Sub API POST 处理失败:', error);
    
    return NextResponse.json(
      { 
        error: error instanceof Error ? error.message : '服务器内部错误',
        details: process.env.NODE_ENV === 'development' ? String(error) : undefined
      },
      { status: 500 }
    );
  }
}
