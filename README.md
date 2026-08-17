# Free VPN Clash Aggregator

这个仓库把 10 个公开的 GitHub Clash/V2Ray 节点项目合并为一个 Clash Meta 配置，失败的上游会被隔离，节点会去重，GitHub Actions 每 15 分钟重新抓取并提交生成文件。

## Clash Verge 导入

仓库发布后，将下面的 `OWNER/REPO` 替换成你的 GitHub 仓库路径，然后在 Clash Verge Rev 的订阅管理中粘贴：

```text
https://raw.githubusercontent.com/OWNER/REPO/main/output/clash.yaml
```

如果仓库是公开的，这个链接会随 Actions 更新自动返回最新版配置。`output/source-status.json` 可查看每个上游最近一次抓取是否成功。

## 本地运行

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt
.venv/Scripts/python scripts/update.py
```

脚本会并行拉取上游、TCP 探活，再用 mihomo 做协议级延迟测试，只保留延迟最低且真实可用的节点。默认最多输出 200 个，节点名带延迟前缀（如 `123ms | HK-1`），并生成 `FAST`（最快约 20 个）和 `AUTO` 两组。

```bash
MAX_NODES=200 python scripts/update.py
```

常用环境变量：`MAX_NODES`（输出上限）、`DELAY_CANDIDATES`（协议测速候选数）、`DISABLE_DELAY_TEST=1`（只做 TCP 探活）。建议不要把上限开得太大，否则 Clash Verge 启动和 url-test 都会变慢。

## 安全与合规

这些节点来自未知的第三方公开服务，不能视为可信 VPN。不要通过它们登录银行、邮箱、代码仓库或传输敏感数据；请遵守所在地区法律和各上游项目许可证。上游项目可能随时删除节点或改变格式，工作流会在全部源失败时退出而保留上一版可用文件。

## 上游项目

见 [`sources.yaml`](sources.yaml)。来源包括 PuddinCat/BestClash、Au1rxx/free-vpn-subscriptions、awesome-vpn/awesome-vpn、vxiaov/free_proxies、ermaozi/get_subscribe、anaer/Sub、ermaozi01/free_clash_vpn、peasoft/NoMoreWalls、NiceVPN123/NiceVPN、chengaopan/AutoMergePublicNodes。
