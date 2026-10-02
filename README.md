# 星载增量包地面复原校验系统

地面归档人员收到星载软件交付的 Base64 Git Pack v2 增量包后，通过本系统确认
目标数据块确实能由包内前序对象逐层复原，避免断裂或越界的差分被误送入长期归档。

仅接受：

- `blob`；
- `OFS_DELTA`；
- 以 `blob` 为根、可任意嵌套的 `OFS_DELTA` 链。

`commit` / `tree` / `tag` / `REF_DELTA` 目标、非对象起点偏移、基对象不在更早
位置、zlib 尾随字节、复制越界、声明长度不符等一律拒绝，并报告**包内首个失败
字节的绝对偏移**，同时页面清除旧成功证据。

## 校验规则

服务严格按 Git Pack v2 规范执行：

1. **Pack 头**：魔数 `PACK`、版本号 `2`、对象计数；
2. **对象走查**：逐对象解析 MSB 续位的变长对象头（类型 3 bit + 尺寸）、
   OFS_DELTA 的 Git 负偏移编码（每进一位先减 1、高位在前），并精确定位每段
   zlib 流的起止（借助 `unused_data`，后随对象头与尾部摘要不被误吞）；
3. **正文覆盖**：最后一个 zlib 流结束位置必须恰好等于尾部摘要起点，否则报告
   未覆盖尾随字节的偏移；
4. **尾部 SHA-1**：对 `PACK` 起到正文末的全部内容重算 SHA-1 并与尾部 20 字节
   比对；
5. **基对象链**：每层 OFS_DELTA 的基偏移必须指向**更早的对象起点**，链根必须
   是 `blob`；
6. **逐层差分**：校验 delta 头声明的源/目标长度，严格解析 copy（0x80 掩码）
   与 insert（低 7 位长度）指令，复制区间越界即报告该操作码的包内绝对偏移，
   最终输出长度必须与声明目标长度一致；
7. **规范 SHA-1**：对复原内容计算 `sha1("blob " + len + NUL + content)`。

成功证据包括：目标类型、解压长度、规范 SHA-1、完整基对象偏移链（含每个对象
的头声明长度、zlib 流区间、OFS 基偏移），以及每层每条 copy 的 `(src,len,dst)`
和 insert 的 `(dst,len,十六进制数据)`。

## 运行（Docker Compose）

宿主机端口可配置，默认 8080：

```bash
# 默认端口
docker compose up --build

# 自定义宿主机端口
HOST_PORT=9090 docker compose up --build
```

启动两个容器：

- `verifier`：HTTP 服务（页面 + `/api/verify` + `/health`），带健康检查；
- `verify`：等待 `verifier` 健康后实际执行验收——构建检查、解码规则测试
  （含与真实 `git repack` 生成 pack 的交叉验证）、针对有效嵌套差分与损坏
  尾部摘要的 HTTP 冒烟，并以**退出码**报告验收结果。

一次性运行验收并按退出码判断（CI 场景）：

```bash
docker compose up --build --abort-on-container-exit --exit-code-from verify
echo $?   # 0 验收通过，非 0 存在失败项
```

验收完成后 `verify` 容器退出，`verifier` 继续提供服务；浏览器访问
`http://localhost:8080`（或自定义端口）即可使用页面。

## 本地开发（无需 Docker、无第三方依赖）

需要 Python 3.11；解码测试中的真实 git 交叉验证需要 `git`。

```bash
# 启动服务
PORT=8080 python3 app/server.py

# 仅跑解码规则测试
python3 -m unittest tests.test_pack -v

# 跑完整验收（先启动服务）
TARGET_URL=http://127.0.0.1:8080 python3 verify/run_acceptance.py
```

## HTTP API

### `GET /health`

```json
{"status": "ok", "service": "pack-verifier"}
```

### `POST /api/verify`

请求：

```json
{ "pack_base64": "<Base64 文本，≤ 256 KiB，允许空白换行>", "offset": 440 }
```

`offset` 可用十进制整数/字符串或 `0x` 十六进制字符串。

成功：`200 {"ok": true, "type": "blob", "length": …, "sha1": …,
"chain": [ … ], "layers": [ … ]}`。

失败：`200 {"ok": false, "error": {"code": …, "message": …,
"offset": <首个失败字节偏移>, "detail": …}}`，响应不含任何旧成功证据字段。

错误码包括：`BAD_SIGNATURE`、`UNSUPPORTED_VERSION`、`TRUNCATED_OBJECT`、
`INVALID_OBJECT_TYPE`、`BASE_NOT_PRIOR`、`ZLIB_ERROR`、`ZLIB_TRUNCATED`、
`DECLARED_SIZE_MISMATCH`、`TRAILING_BODY_BYTES`、`TRAILER_MISMATCH`、
`TYPE_NOT_ALLOWED`、`ROOT_TYPE_NOT_BLOB`、`OFFSET_NOT_OBJECT_START`、
`OFFSET_OUT_OF_RANGE`、`DELTA_SOURCE_SIZE_MISMATCH`、
`DELTA_TARGET_SIZE_MISMATCH`、`DELTA_COPY_OUT_OF_RANGE`、
`INVALID_DELTA_OPCODE`、`DELTA_OPERAND_TRUNCATED` 等。

## 目录结构

```
app/
  pack.py            严格 Pack v2 解析 / OFS 链复原 / 差分校验（纯标准库）
  server.py          HTTP 服务：/、/health、/api/verify
  static/index.html  校验页面（fetch 真实 API）
  Dockerfile         verifier 镜像
tests/
  packbuilder.py     按规范手工合成 pack 的测试夹具
  test_pack.py       31 项解码规则测试（含真实 git pack 交叉验证）
verify/
  run_acceptance.py  验收入口：构建检查 + 解码测试 + HTTP 冒烟，退出码报告
  Dockerfile         verify 镜像
docker-compose.yml   可配置宿主机端口、健康检查、验收依赖编排
```
