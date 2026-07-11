# IDA-MCP

一个 [Model Context Protocol](https://modelcontextprotocol.io)（MCP）
服务器，通过 HTTP 将 IDA Pro 的静态逆向能力暴露给兼容 MCP 的 AI 客户端。

支持**多 IDA 实例**同时工作——独立 Server 进程统一管理，所有 IDA 平等连接为 Worker。
首个 IDA 自动拉起 Server；最后一个 Worker 断连并连续空闲 3 秒后发起退出。

---

## 特性

- **多实例。** 独立 MCP Server 进程管理多个 IDA 实例，通过 `f` 参数路由到指定文件。
- **客户端无关。** 通过标准 MCP over streamable HTTP 通信。任何兼容的 MCP 客户端
  均可使用；客户端只负责连接，从不启动服务器。
- **分层设计。** 原子层封装 IDA API；组合层把原子装配成面向 LLM 认知任务、
  体积可控的工具。
- **LLM 友好的数据契约。** 所有整数以字符串形式返回（地址用十六进制，其余用十进制），
  彻底消除 64 位整数精度丢失，也免去模型做任何进制换算。
- **意图工具。** 在"一次调用对应一个 IDA 动作"的能力工具之外，更高层的意图工具能
  在单次调用中聚合完成一个推理任务所需的全部信息。
- **自动启停。** Server 在首个 IDA 连接时自动启动；最后一个 Worker 断连并
  连续空闲 3 秒后发起退出，期间有 Worker 重连会取消退出。
- **断服自愈。** Worker 连续连接失败会重新确保 Server 存在；IDA 暂无输入文件时
  插件持续等待，之后打开文件仍能注册。
- **默认只读。** Worker 使用中央工具 allowlist，并在 handler/IDA API 前拒绝全部
  写工具和未知工具。只有启动 IDA 前精确设置 `IDA_MCP_ALLOW_WRITE=1` 才启用写。
- **精确兼容握手。** Server/Worker 校验内部协议、实现版本、完整工具 manifest 和
  read/write/Hex-Rays capabilities；部分部署或旧进程不会静默降级连接。
- **38 个工具。** 34 个能力工具 + 4 个意图工具，覆盖概览、反编译、反汇编、搜索、xref、
  类型、局部变量、注释、patch、图关系和聚合分析。

---

## 架构

```
┌────────────┐   MCP over HTTP    ┌──────────────────────────────┐
│  MCP 客户端 │ ◄────────────────► │  MCP Server (独立进程)         │
│ (AI agent) │  streamable-http   │  HTTP :8765  + 路由 + 注册表   │
└────────────┘                    └──┬──────┬──────┬───────────┘
                                     │TCP   │TCP   │TCP
                                     │:8766 │:8766 │:8766
                              ┌──────┘      │      └──────┐
                              ▼             ▼             ▼
                           IDA #1        IDA #2        IDA #3
                          (Worker)      (Worker)      (Worker)
                          随机 call_port 随机 call_port 随机 call_port
```

独立 Server 进程（`ida_mcp_standalone.py`）由首个 IDA 的 `ida_mcp.py` 插件通过
`subprocess.Popen` 启动，使用 IDAPython 所属的 Python 安装环境。所有 IDA 实例
平等——全部作为 Worker 通过 TCP 连接。

Server 生命周期为 `STARTING -> ACTIVE -> DRAINING -> STOPPING`。Registry 使用
Condition + generation；DRAINING 期间的新注册会取消旧 deadline，STOPPING 后
probe/register 返回不可用。3 秒表示发起优雅退出，不是在途请求的强制终止上限。

进程内的两个职责层：

| 层 | 模块 | 职责 |
|----|------|------|
| **工具层** | `ida_mcp/tools/` | 语义组合；一个工具对应一个稳定的 LLM 认知动作。唯一允许组合原子的层。意图工具独立于能力工具。 |
| **原子层** | `ida_mcp/ida_api/` | 对 IDA API 的薄封装，单一职责。通过 `execute_sync` 封送到 IDA 主线程执行，不做组合。 |

---

## 项目结构

```
ida_mcp.py                插件入口（PLUGIN_ENTRY）；自动启动/连接 Server。
ida_mcp_standalone.py     独立 Server 入口脚本。
requirements.txt          Standalone Server 的锁定 Python 依赖。
ida_mcp/                  实现包
├── __init__.py
├── server.py            程序入口：导入工具、execute_tool 调度。
├── _base.py             共享基础：mcp 实例、常量、错误翻译、地址/数字转换、路由辅助。
├── _contracts.py        版本化游标的编码、校验与工具/目标绑定契约。
├── categories.py        确定性的导入分类表。
├── launcher.py          定位 IDAPython 所属 Python，拒绝 ida.exe/PATH 回退。
├── standalone.py        独立 MCP Server（HTTP + TCP + 事件驱动生命周期）。
├── multi.py             Worker 与 InternalServer（TCP 注册/转发）。
├── router.py            工具调用路由（根据 file_id 分发到远程 Worker）。
├── registry.py          FileEntry + Registry（generation、Condition、原子关闭门）。
├── protocol.py          TCP 消息编解码（4 字节长度前缀 + JSON）。
├── runtime_contract.py  协议/实现版本、工具 allowlist/manifest、ACK 与 capability 契约。
├── ida_api/             原子层（Layer 2），按功能域拆分
│   ├── __init__.py      汇出全部原子。
│   ├── core.py          run_in_main、IDAError、常量。
│   ├── functions.py     反编译 / 有界反汇编 / 函数信息。
│   ├── binary.py        段 / 导入 / 导出 / 字符串 / 命名数据。
│   ├── xrefs.py         交叉引用 / 调用关系 / 基本块。
│   ├── names.py         名称 / 字节 / 重命名 / 打补丁 / 行注释。
│   ├── search.py        文本 / 字节 / 立即数搜索。
│   ├── types.py         类型系统（struct/enum/typedef/原型）。
│   ├── hexrays.py       局部变量 / 伪代码行地址映射。
│   ├── comments.py      函数 / 前置 / 后置注释。
│   ├── meta.py          二进制元信息 / 目标指纹 / 分析状态 / switch / 栈帧。
│   └── patch.py         undefine / make code / make data / make string。
└── tools/               工具层（Layer 3）
    ├── __init__.py      导入各域子模块以触发 @mcp.tool 注册。
    ├── overview.py      check_connection / analysis_status / binary_overview / binary_info / list_files。
    ├── functions.py     analyze_function / decompile / disassemble / decompile_with_addresses / get_stack_frame / get_switch。
    ├── search.py        search / trace_data / cross_references。
    ├── graph.py         call_graph / function_reachability。
    ├── types.py         类型系统工具。
    ├── lvars.py         局部变量工具。
    ├── annotate.py      rename / comment / patch / make_* / undefine。
    └── intent.py        意图工具（explore_function/explore_data/survey_capabilities/review_string_usage）。
```

> **依赖单向**：`tools/*` → `_base` → `ida_api`；分页工具还直接依赖
> `_contracts`。Server/Worker/Router/Registry 共享 `runtime_contract`，工具子模块之间
> 互不依赖。

---

## 前置条件

- **当前验证版本：IDA Pro 9.4。** IDA 9.0-9.3 尚未经过本轮兼容性验证。
- 当前最终验证环境包含 Hex-Rays。`analysis_status` 会报告其 readiness，
  `disassemble` 的实现不依赖反编译器；无 Hex-Rays 环境尚未经过本轮最终验证。
- 在 **IDAPython 所属 Python 环境**中安装交付物锁定的依赖。在
  `IDA-MCP-Plugin` 目录执行：
  ```
  <idapython-python.exe> -m pip install -r requirements.txt
  ```

插件会从 IDAPython 的 `sys.base_prefix`/`sys.prefix` 查找真正的 Python
解释器，不会使用可能指向 `ida.exe` 的 `sys.executable`。自动发现失败时可设置
`IDA_MCP_PYTHON` 为对应 `python.exe` 的完整路径。

Worker 默认只读。需要使用重命名、注释、类型修改或 patch 等写工具时，必须在启动
对应 IDA 进程前精确设置：

```powershell
$env:IDA_MCP_ALLOW_WRITE = "1"
& "C:\Path\To\IDA\ida.exe"
```

将示例路径替换为实际的 IDA 可执行文件路径。

只有字符串 `1` 启用写；未设置、空值、`0` 或其它值都 fail closed。权限在 Worker
构造时固定，修改环境变量后必须重启对应 IDA。先用 `list_files` 检查目标的
`read_only` 和 `capabilities.write`，不要根据工具是否出现在列表中猜测权限。

---

## 安装

将以下四个项一起复制到 IDA 的 `plugins` 目录：

```
<IDA plugins 目录>/
├── ida_mcp.py
├── ida_mcp_standalone.py
├── requirements.txt
└── ida_mcp/          （完整包）
```

---

## 使用

1. 启动 IDA Pro，打开第一个目标二进制，等待自动分析完成。
2. 插件检测到尚无 Server 在运行，自动启动独立 Server；当前 IDA 作为 Worker 连入。
3. Output 窗口输出：

   ```
   [ida-mcp] No server found, launching...
   [ida-mcp-server] Listening on http://127.0.0.1:8765/mcp (38 tools)
   [ida-mcp] Worker | ntoskrnl.exe (5bb8fc99a3417d2e)
   ```

4. 启动第二个 IDA，打开另一个二进制。插件检测到 Server 已在运行，直接作为 Worker 连入：

   ```
   [ida-mcp] Worker | ACE-BASE.sys (c09a60a08b91306f)
   ```

5. 关闭所有 IDA 后，Server 在连续 3 秒没有 Worker 时发起退出；若仍有正在
   执行的 MCP 请求，则会先进行优雅关闭。

IDA 启动但尚未打开输入文件时，Worker 会持续等待。若等待期间 Server 因启动保护
到期而退出，文件出现后 Worker 会重新确保 Server 可用。

### 多实例使用

除 `list_files` 外，其余 37 个工具均支持 `f` 参数指定目标文件。先调用
`list_files` 获取可用文件 ID：

```
list_files → {
  "count": "2",
  "files": [
    {"fid": "5bb8fc99a3417d2e", "name": "ntoskrnl.exe", "read_only": true,
     "capabilities": {"read": true, "write": false, "hexrays": true,
                      "worker_write_gate": true}},
    {"fid": "c09a60a08b91306f", "name": "ACE-BASE.sys", "read_only": true,
     "capabilities": {"read": true, "write": false, "hexrays": true,
                      "worker_write_gate": true}}
  ]
}
decompile(f="5bb8fc99a3417d2e", identifier="NtCreateFile")  → ntoskrnl.exe
decompile(f="c09a60a08b91306f", identifier="DriverEntry")  → ACE-BASE.sys
```

单实例时可省略 `f` 参数。

### MCP 客户端配置

```json
{
  "mcp": {
    "ida": {
      "type": "remote",
      "url": "http://127.0.0.1:8765/mcp"
    }
  }
}
```

---

## 数据契约

- **所有整数以字符串返回。** 地址为十六进制（`"0x401000"`）；其余数值为十进制。
- **入参接受字符串。** 地址/标识符参数接受符号名、十六进制字符串或十进制字符串。
- **字节为十六进制字符串。**
- Worker 默认拒绝写工具并返回 `READ_ONLY`。显式启用后，修改数据库的写操作会在
  可能的情况下校验其效果，且**从不改动原始输入文件**。

---

## 工具

工具分为两类：

- **能力工具** —— 一个工具对应一个 IDA 动作。
- **意图工具（标注【意图】）** —— 一个工具对应一个推理任务，内部编排多个动作并聚合结果。

### 意图工具
| 工具 | 用途 |
|------|------|
| `explore_function` | **【意图】** 聚合伪代码 + 被调/调用者 + 引用字符串 + 特征 + 分类提示 |
| `explore_data` | **【意图】** 对 `identifier` 建立数据画像：可配置 byte window + 精确类型/字符串 + typed pointer chain + 四类引用独立续页；窗口/续页参数为 `read_offset`、`read_size`、`dereference_depth`、`xref_limit`、`cursor`。 |
| `survey_capabilities` | **【意图】** 按能力面分桶的导入；每个已分类 API 最多列出 5 个调用函数，该子列表当前不单独报告截断。 |
| `review_string_usage` | **【意图】** 匹配字符串 + 引用函数 + 伪代码片段 |

### 概览与导航
| 工具 | 用途 |
|------|------|
| `check_connection` | 确认服务器可响应且已加载数据库。 |
| `analysis_status` | 非阻塞读取 auto-analysis、Hex-Rays 与 IDA 版本 readiness。 |
| `binary_overview` | 入口点、按类别分桶的导入、特征字符串、段布局。 |
| `binary_info` | 文件格式、处理器、位数、字节序、image base、地址范围。 |
| `list_files` | 列出所有已连接的 IDA 实例及 read-only、read/write/Hex-Rays、协议/实现/manifest capabilities。 |

### 函数分析
| 工具 | 用途 |
|------|------|
| `analyze_function` | 伪代码、被调/调用者、引用字符串、结构特征；可按需附有界 CFG 与静态 callsite。 |
| `decompile` | 仅取伪代码；内部地址可取 address-centred 切片，失败时降级为反汇编。 |
| `disassemble` | 有界读取指令、bytes 与 IDA 已记录的静态 flow refs；不保证解析间接目标。 |
| `decompile_with_addresses` | 为伪代码行附 best-effort 语句地址与独立引用目标，不承诺一对一映射。 |
| `get_stack_frame` | 栈帧变量布局。 |
| `get_switch` | switch/跳转表的分支值与目标地址。 |

### 搜索与数据流
| 工具 | 用途 |
|------|------|
| `search` | 稳定分页搜索函数、字符串、导入、命名数据、导出或立即数；用 `next_cursor` 续页。 |
| `trace_data` | 将引用按函数聚合，返回最多 30 个函数组；每组给代表站点、站点数和代码上下文，并用 `truncated` 标记超限，当前不可续页。 |
| `cross_references` | 按 address/function scope 稳定分页引入/引出引用；每项含函数、指令和 xref type，但不附代码上下文片段。 |

### 调用图
| 工具 | 用途 |
|------|------|
| `call_graph` | N 层调用图（被调 / 调用者 / 双向）。 |
| `function_reachability` | 判断一个函数能否到达另一个，并给出路径。 |

### 类型
| 工具 | 用途 |
|------|------|
| `list_types` | 按 ordinal 稳定枚举本地类型；`name_filter` 不区分大小写，`cursor` 可继续下一页；`kind_status` 区分精确 kind 与单项不可用。 |
| `get_type` | 按精确名称查看类型；members 用独立 `cursor` 续页，C definition 用 `definition_offset` / `definition_limit` 字符窗口读取。 |
| `create_type` / `delete_type` | 用 C 声明定义或删除本地类型。 |
| `apply_type` | 把 C 类型应用到某地址。 |
| `get_function_prototype` / `set_function_prototype` | 读取/设置函数原型。 |

### 局部变量
| 工具 | 用途 |
|------|------|
| `list_local_variables` | 列出函数的局部变量与参数。 |
| `rename_local_variable` | 重命名反编译器中的局部变量。 |
| `set_local_variable_type` | 修改反编译器中局部变量的类型。 |

### 命名、注释与打补丁
| 工具 | 用途 |
|------|------|
| `rename` | 重命名函数/全局/地址（冲突时给出替代建议名）。 |
| `get_comment` / `set_comment` | 读写行注释、函数注释、前置或后置注释。 |
| `patch_bytes` | 打补丁修改数据库字节（回读校验；不改动输入文件）。 |
| `undefine` | 将某项还原为未定义字节。 |
| `make_code` / `make_data` / `make_string` | 将字节转换为代码、数据或字符串字面量。 |

---

## 说明

- 首次启动独立 Server 时需确保 :8765 和 :8766 可用；已有 compatible Server 时插件会
  复用它，而不是要求端口无人监听。
- 启用写后，本机其它进程属于当前 loopback 信任边界；不要在不受信任的桌面会话中
  设置 `IDA_MCP_ALLOW_WRITE=1`。
- 通过写操作工具所做的数据库修改保存在 IDA 数据库（`.idb`/`.i64`）中，而非原始二进制文件。
- Server 在最后一个 Worker 断连并连续空闲 3 秒后发起退出；期间的新注册会
  取消退出，再次打开 IDA 时也会自动确保 Server 可用。
- 如果出现 `Load file ... ida_mcp_standalone.py as`，说明仍在运行旧启动逻辑，
  把 `ida.exe` 误当作 Python。确认已完整部署 `launcher.py` 并重启全部 IDA；必要时
  设置 `IDA_MCP_PYTHON` 指向 IDAPython 所属 `python.exe`。
- 当前 R1-R4 最终 GUI/MCP gate 使用单个 Worker；同时连接多个 Worker 的行为尚未在
  本轮修复中重新执行完整回归。
- 修改 `ida_mcp.py`、`ida_mcp_standalone.py` 或 `ida_mcp/` 后，需重新部署并重启
  IDA，新代码才会生效。
- `ida_mcp.py`、`ida_mcp_standalone.py`、`requirements.txt` 和完整 `ida_mcp/` 必须
  作为同一版本一起部署。
  若输出提示 protocol/implementation/manifest incompatibility，先关闭全部旧 IDA 与
  standalone Server，完成整套部署后再启动；插件不会对旧内部协议静默降级。
