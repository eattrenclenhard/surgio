import { z } from 'zod'
import { Base64 } from 'js-base64';

import {
  CustomProviderConfig,
  NodeTypeEnum,
  PossibleNodeConfigType,
  VmessNodeConfig,
} from '../types'
import { SurgioError } from '../utils'
import {
  WireguardNodeConfigValidator,
  ShadowsocksNodeConfigValidator,
  HttpNodeConfigValidator,
  HttpsNodeConfigValidator,
  TrojanNodeConfigValidator,
  ShadowsocksrNodeConfigValidator,
  Socks5NodeConfigValidator,
  VmessNodeConfigValidator,
  SnellNodeConfigValidator,
  TuicNodeConfigValidator,
  Hysteria2NodeConfigValidator,
  VlessNodeConfigValidator,
} from '../validators'

import Provider from './Provider'
import { GetNodeListFunction, GetNodeListParams } from './types'

export default class CustomProvider extends Provider {
  public readonly nodeList:
    | unknown[]
    | ((params: GetNodeListParams) => Promise<unknown[]>)
  public readonly underlyingProxy?: string

  constructor(name: string, config: CustomProviderConfig) {
    super(name, config)

    const schema = z.object({
      nodeList: z.union([
        z.array(z.any()),
        z.function().args(z.any()).returns(z.any()),
      ]),
      underlyingProxy: z.ostring(),
    })
    const result = schema.safeParse(config)

    // istanbul ignore next
    if (!result.success) {
      throw new SurgioError('CustomProvider 配置校验失败', {
        cause: result.error,
        providerName: name,
      })
    }

    this.nodeList = result.data.nodeList
    this.underlyingProxy = result.data.underlyingProxy
  }

  public getNodeList: GetNodeListFunction = async (
    params = {},
  ): Promise<Array<PossibleNodeConfigType>> => {
    let nodeList: any[]
    const parsedNodeList: PossibleNodeConfigType[] = []

    if (typeof this.nodeList === 'function') {
      nodeList = await this.nodeList(params)
    } else {
      nodeList = this.nodeList
    }

    nodeList.forEach((node, index) => {
      try {
        if (node.base64) {
          const base64Pattern = /^(ss|vmess):\/\/([A-Za-z0-9+/=]+)(#.*)?$/;
          const match = node.base64.match(base64Pattern);

          if (match) {
            const nodeTypeMap: { [key: string]: NodeTypeEnum } = {
              ss: NodeTypeEnum.Shadowsocks,
              vmess: NodeTypeEnum.Vmess,
            };

            const nodeType = nodeTypeMap[match[1]];
            const base64String = match[2];
            const decoded = Base64.decode(base64String);
            switch (nodeType) {
              case NodeTypeEnum.Shadowsocks:
                // (nodeType === NodeTypeEnum.Shadowsocks)
                const [method, passwordWithHost, port] = decoded.split(':');
                const [password, hostname] = passwordWithHost.split('@');

                node = {
                  ...node,
                  type: nodeType,
                  hostname,
                  port: parseInt(port, 10),
                  method,
                  password,
                };
                break;
              
              case NodeTypeEnum.Vmess:
                break;
              default:
                console.error('Base64 extraction is only supported for shadowsocks and vmess');
                break;
            }
          } else {
            console.error('Invalid base64 format');
            throw new TypeError('Invalid base64 format');
          }
        }

        const type = node.type as NodeTypeEnum;

        // istanbul ignore next
        if (node['udp-relay']) {
          throw new Error('udp-relay 已废弃, 请使用 udpRelay')
        }

        // istanbul ignore next
        if (node['obfs-host']) {
          throw new Error('obfs-host 已废弃, 请使用 obfsHost')
        }

        // istanbul ignore next
        if (node['obfs-uri']) {
          throw new Error('obfs-uri 已废弃, 请使用 obfsUri')
        }

        let parsedNode = (() => {
          switch (type) {
            case NodeTypeEnum.Shadowsocks:
              return ShadowsocksNodeConfigValidator.parse(node)

            case NodeTypeEnum.Shadowsocksr:
              return ShadowsocksrNodeConfigValidator.parse(node)

            case NodeTypeEnum.Vmess:
              return VmessNodeConfigValidator.parse(node)

            case NodeTypeEnum.Trojan:
              return TrojanNodeConfigValidator.parse(node)

            case NodeTypeEnum.Socks5:
              return Socks5NodeConfigValidator.parse(node)

            case NodeTypeEnum.HTTP:
              return HttpNodeConfigValidator.parse(node)

            case NodeTypeEnum.HTTPS:
              return HttpsNodeConfigValidator.parse(node)

            case NodeTypeEnum.Snell:
              return SnellNodeConfigValidator.parse(node)

            case NodeTypeEnum.Tuic:
              return TuicNodeConfigValidator.parse(node)

            case NodeTypeEnum.Wireguard:
              return WireguardNodeConfigValidator.parse(node)

            case NodeTypeEnum.Hysteria2:
              return Hysteria2NodeConfigValidator.parse(node)

            case NodeTypeEnum.Vless:
              return VlessNodeConfigValidator.parse(node)

            default:
              
              throw new TypeError(`无法识别的节点类型：${type}`);
          }
        })()

        if (this.underlyingProxy && !parsedNode.underlyingProxy) {
          parsedNode.underlyingProxy = this.underlyingProxy
        }

        if (parsedNode.type === NodeTypeEnum.Vmess) {
          parsedNode = this.prepareVmessNodeConfig(parsedNode)
        }

        parsedNodeList.push(parsedNode)
      } catch (err) {
        console.error(`Error parsing node at index ${index}:`, err);
      }
    });

    return parsedNodeList;
  }

  public prepareVmessNodeConfig(node: VmessNodeConfig): VmessNodeConfig {
    if (node.host) {
      node.sni = node.host
    }

    if (node.wsHeaders) {
      if (!node.wsOpts) {
        node.wsOpts = {
          headers: node.wsHeaders,
          path: node.path || '/',
        }
      } else if (node.wsOpts.headers) {
        throw new Error('wsOpts.headers 和 wsHeaders 不能同时存在')
      } else {
        node.wsOpts.headers = node.wsHeaders
      }
    }

    if (node.network === 'ws' && node.path) {
      throw new Error('请将 path 移动到 wsOpts.path')
    }

    if (node.network === 'h2' && node.path) {
      throw new Error('请将 path 移动到 h2Opts.path')
    }

    if (node.network === 'http' && node.path) {
      throw new Error('请将 path 移动到 httpOpts.path')
    }

    return node
  }
}
