# packv — Git Pack v2 目标数据块复原校验

地面归档人员收到星载软件交付的增量包后，用本服务确认包内**指定偏移**的
目标数据块确实能由包内前序对象复原，避免断裂或越界的差分被误送入长期归档。

- 仅接受 `blob`、`OFS_DELTA` 及以它们为基的嵌套 `OFS_DELTA`；
  出现 `commit/tree/tag/REF_DELTA` 等一律拒绝。
- 先核对 `PACK` 头、版本 v2、对象计数，以及**覆盖整个 pack 正文**的
  尾部 SHA-1；再按变长对象头与 OFS 变长编码精确定位每段 zlib 流。
- 逐层应用差分，每层声明的源 / 目标长度必须与实际复制结果一致；
  复制越界、插入截断、保留零号指令、最终长度不符均拒绝。
- 任何失败都返回**首个失败字节偏移**，页面同时清除旧成功证据。
- 结论全部由真实后端 `POST /api/verify` 返回，前端不做任何本地判定。
- 零第三方依赖：服务端仅用 Python 3.11 标准库。

## 目录结构

```
app.py                 标准库 HTTP 服务（页面 + /healthz + /api/verify）
packv/parser.py        Pack 解析、OFS 基链复原、差分应用与证据收集
static/                单页前端（index.html / app.js / styles.css）
tests/test_pack.py     解码规则单元测试（含真实 git pack 交叉校验）
tests/fixtures.py      合法嵌套差分 / 越界 / 损坏尾部等构造夹具
scripts/verify.py      验收：构建检查 + 单元测试 + HTTP 冒烟
scripts/smoke_http.py  针对运行中服务的 HTTP 冒烟
Dockerfile             web 服务镜像
Dockerfile.verify      verify 验收镜像（额外安装 git 做真实包交叉校验）
docker-compose.yml     web + verify 两服务
```

## 本地运行（无需 Docker）

```bash
python3 app.py                       # 默认 0.0.0.0:8080
PACKV_PORT=9000 python3 app.py       # 自定义端口
# 浏览器打开 http://127.0.0.1:8080
```

健康检查：

```bash
curl -s http://127.0.0.1:8080/healthz
# {"status": "ok"}
```

## Compose 运行（宿主机端口可配置）

```bash
cp .env.example .env                 # 按需修改 PACKV_HOST_PORT
docker compose up -d web             # 启动 web，端口由 .env 决定
docker compose run --rm verify       # 一次性验收（见下）
```

`verify` 容器会等待 `web` 健康后，**实际执行**：

1. 构建检查（编译全部 Python 源）；
2. 解码规则单元测试（含调用容器内 `git pack-objects` 生成真实
   OFS_DELTA pack 的交叉校验）；
3. 针对 `http://web:8080` 的 HTTP 冒烟，覆盖：
   - 健康响应；
   - **有效两层嵌套 OFS_DELTA** 的完整复原（类型、长度、规范 SHA-1、
     基链偏移、每层 copy/insert 证据）；
   - **损坏尾部摘要**（翻转包尾 SHA-1 首字节，断言失败偏移为正文末尾）；
   - 差分复制越界（断言 delta 起点与解压差分内指令偏移）；
   - 目标偏移不落对象起点、非法 Base64、首页可获取。

验收以退出码报告结果：`0` 通过，非 `0` 失败。

不使用 Docker 时可在本机等价运行：

```bash
python3 scripts/verify.py                    # 自启服务后冒烟
BASE_URL=http://127.0.0.1:8080 python3 scripts/verify.py   # 外部服务模式
```

## API

### `POST /api/verify`

请求：

```json
{ "pack_base64": "<Base64 编码的 pack v2>", "offset": 178 }
```

- Base64 解码后不得超过 **256 KiB**；粘贴时允许含空白。
- `offset` 为目标对象相对 pack 起始的字节偏移，必须为非负整数。

成功 `200`：

```json
{
  "ok": true,
  "object_count": 3,
  "pack_size": 213,
  "pack_sha1": "<覆盖正文的摘要>",
  "target": { "offset": 152, "type": "ofs_delta",
              "inflated_length": 57, "sha1": "<规范 blob SHA-1>" },
  "root_blob": { "offset": 12, "declared_size": 48, "actual_size": 48 },
  "base_chain_offsets": [12, 86, 152],
  "final_length": 57,
  "final_sha1": "<sha1(\"blob 57\\0\" + 复原内容)>",
  "layers": [
    {
      "delta_offset": 86, "base_offset": 12,
      "base_size_declared": 48, "base_size_actual": 48,
      "result_size_declared": 48, "result_size_actual": 48,
      "result_sha1": "<本层产物 SHA-1>",
      "steps": [
        { "kind": "insert", "cmd_offset": 2, "length": 4,
          "dst_offset": 0, "bytes_hex": "42424242" },
        { "kind": "copy", "cmd_offset": 7, "src_offset": 4,
          "length": 44, "dst_offset": 4, "bytes_hex": "…" }
      ]
    }
  ]
}
```

失败 `200`（业务校验失败，便于前端统一渲染）：

```json
{ "ok": false, "error": "复制越界：…", "offset": 152, "detail_offset": 2 }
```

- `offset`：相对 pack 起始的绝对字节偏移（首个失败字节）；
- `detail_offset`：当错误位于某对象**解压后正文**（如差分指令）时，
  额外给出相对该对象解压数据起点的偏移；
- 请求格式错误（非法 JSON / Base64、字段缺失、超长）返回 `400/413`。

## 失败场景与首个失败字节偏移

| 场景 | 报告偏移 |
| --- | --- |
| 非 `PACK` 签名 / 版本非 2 | `0` / `4` |
| 对象计数不符、对象间垃圾字节 | 越界或首个垃圾字节 |
| 尾部 SHA-1 不符 | 正文末尾（包尾起始） |
| 压缩流后、包尾前有尾随字节 | 首个尾随字节（流终点） |
| 目标类型不在白名单 | 目标对象起点 |
| 目标偏移不落对象起点 | 该偏移本身 |
| 基对象不在此前位置 / 非对象起点 | delta 的压缩流区域 |
| 复制越界、零号指令、长度不符 | delta 对象起点 + 解压数据内偏移 |

## 测试

```bash
python3 -m unittest tests.test_pack -v   # 31 项
```
