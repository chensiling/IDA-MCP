# IDA-MCP

一个 [Model Context Protocol](https://modelcontextprotocol.io)（MCP）
服务器，通过 HTTP 将 IDA Pro 的静态逆向能力暴露给兼容 MCP 的 AI 客户端。

支持**多 IDA 实例**同时工作——独立 Server 进程统一管理，所有 IDA 平等连接为 Worker。
首个 IDA 自动拉起 Server，最后一个断连后 Server 自动退出。

---

## 特性

- **多实例。** 独立 MCP Server 进程管理多个 IDA 实例，通过 `f` 参数路由到指定文件。
- **客户端无关。** 通过标准 MCP over streamable HTTP 通信。任何兼容的 MCP 客户端
  均可使用；客户端只负责连接，从不启动服务器。
- **分层设计。** 薄薄的原子层封装 IDA API；组合层把原子装配成面向 LLM 认知任务、
  体积可控的工具。
- **LLM 友好的数据契约。** 所有整数以字符串形式返回（地址用十六进制，其余用十进制），
  彻底消除 64 位整数精度丢失，也免去模型做任何进制换算。
- **意图工具。** 在"一次调用对应一个 IDA 动作"的能力工具之外，更高层的意图工具能
  在单次调用中聚合完成一个推理任务所需的全部信息。
- **自动启停。** Server 在首个 IDA 连接时自动启动，在最后一个 IDA 断连 30 秒后自动退出。

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
`subprocess.Popen` 启动，使用 IDA 内嵌的 Python。所有 IDA 实例平等——全部作为
Worker 通过 TCP 连接。

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
ida_mcp/                  实现包
├── __init__.py
├── server.py            程序入口：导入工具、execute_tool 调度。
├── _base.py             共享基础：mcp 实例、常量、错误翻译、地址/数字转换、路由辅助。
├── categories.py        确定性的导入分类表。
├── standalone.py        独立 MCP Server（HTTP + TCP + 空闲监控）。
├── multi.py             Worker 与 InternalServer（TCP 注册/转发）。
├── router.py            工具调用路由（根据 file_id 分发到远程 Worker）。
├── registry.py          FileEntry + Registry（线程安全的文件注册表）。
├── protocol.py          TCP 消息编解码（4 字节长度前缀 + JSON）。
├── ida_api/             原子层（Layer 2），按功能域拆分
│   ├── __init__.py      汇出全部原子。
│   ├── core.py          run_in_main、IDAError、常量。
│   ├── functions.py     反编译 / 反汇编 / 函数信息。
│   ├── binary.py        段 / 导入 / 导出 / 字符串。
│   ├── xrefs.py         交叉引用 / 调用关系 / 基本块。
│   ├── names.py         名称 / 字节 / 重命名 / 打补丁 / 行注释。
│   ├── search.py        文本 / 字节 / 立即数搜索。
│   ├── types.py         类型系统（struct/enum/typedef/原型）。
│   ├── hexrays.py       局部变量 / 伪代码行地址映射。
│   ├── comments.py      函数 / 前置 / 后置注释。
│   ├── meta.py          二进制元信息 / switch / 栈帧。
│   └── patch.py         undefine / make code / make data / make string。
└── tools/               工具层（Layer 3）
    ├── __init__.py      导入各域子模块以触发 @mcp.tool 注册。
    ├── overview.py      check_connection / binary_overview / binary_info / list_files。
    ├── functions.py     analyze_function / decompile / decompile_with_addresses / get_stack_frame / get_switch。
    ├── search.py        search / trace_data / cross_references。
    ├── graph.py         call_graph / function_reachability。
    ├── types.py         类型系统工具。
    ├── lvars.py         局部变量工具。
    ├── annotate.py      rename / comment / patch / make_* / undefine。
    └── intent.py        意图工具（explore_function/explore_data/survey_capabilities/review_string_usage）。
```

> **依赖单向**：`tools/*` → `_base` → `ida_api`，工具子模块之间互不依赖。

---

## 前置条件

- IDA Pro 9.0 或更新版本。
- Hex-Rays 反编译器。
- 在 **IDA 内嵌的解释器**中安装 **MCP Python SDK**：
  ```
  <ida-内嵌-python> -m pip install mcp
  ```

---

## 安装

将以下三个项一起复制到 IDA 的 `plugins` 目录：

```
<IDA plugins 目录>/
├── ida_mcp.py
├── ida_mcp_standalone.py
└── ida_mcp/          （完整包）
```

---

## 使用

1. 启动 IDA Pro，打开第一个目标二进制，等待自动分析完成。
2. 插件检测到尚无 Server 在运行，自动启动独立 Server；当前 IDA 作为 Worker 连入。
3. Output 窗口输出：

   ```
   [ida-mcp] No server found, launching...
   [ida-mcp-server] Listening on http://127.0.0.1:8765/mcp
   [ida-mcp] Worker | ntoskrnl.exe (5bb8fc99)
   ```

4. 启动第二个 IDA，打开另一个二进制。插件检测到 Server 已在运行，直接作为 Worker 连入：

   ```
   [ida-mcp] Worker | ACE-BASE.sys (c09a60a0)
   ```

5. 关闭所有 IDA 后，Server 在 30 秒内检测到无连接，自动退出。

### 多实例使用

所有工具均支持 `f` 参数指定目标文件。先调用 `list_files` 获取可用文件 ID：

```
list_files → [{fid: "5bb8fc99", name: "ntoskrnl.exe"}, {fid: "c09a60a0", name: "ACE-BASE.sys"}]
decompile(f="5bb8fc99", identifier="NtCreateFile")  → ntoskrnl.exe
decompile(f="c09a60a0", identifier="DriverEntry")     → ACE-BASE.sys
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
- 修改数据库的写操作会在可能的情况下校验其效果，且**从不改动原始输入文件**。

---

## 工具

工具分为两类：

- **能力工具** —— 一个工具对应一个 IDA 动作。
- **意图工具（标注【意图】）** —— 一个工具对应一个推理任务，内部编排多个动作并聚合结果。

### 意图工具
| 工具 | 用途 |
|------|------|
| `explore_function` | **【意图】** 聚合伪代码 + 被调/调用者 + 引用字符串 + 特征 + 分类提示 |
| `explore_data` | **【意图】** 数据画像：类型 + 字节/字符串值 + 读者/写者/取址者分类 |
| `survey_capabilities` | **【意图】** 按能力面分桶的导入 + 每 API 的调用者 |
| `review_string_usage` | **【意图】** 匹配字符串 + 引用函数 + 伪代码片段 |

### 概览与导航
| 工具 | 用途 |
|------|------|
| `check_connection` | 确认服务器可响应且已加载数据库。 |
| `binary_overview` | 入口点、按类别分桶的导入、特征字符串、段布局。 |
| `binary_info` | 文件格式、处理器、位数、字节序、image base、地址范围。 |
| `list_files` | 列出所有已连接的 IDA 实例（file_id、名称、架构）。 |

### 函数分析
| 工具 | 用途 |
|------|------|
| `analyze_function` | 伪代码、被调/调用者、引用字符串、结构特征。 |
| `decompile` | 仅取伪代码；失败时降级为反汇编。 |
| `decompile_with_addresses` | 逐行标注对应地址的伪代码。 |
| `get_stack_frame` | 栈帧变量布局。 |
| `get_switch` | switch/跳转表的分支值与目标地址。 |

### 搜索与数据流
| 工具 | 用途 |
|------|------|
| `search` | 带上下文地搜索函数、字符串、导入或立即数。 |
| `trace_data` | 指向目标的全部交叉引用，附代码上下文。 |
| `cross_references` | 引入/引出的引用列表（仅结构）。 |

### 调用图
| 工具 | 用途 |
|------|------|
| `call_graph` | N 层调用图（被调 / 调用者 / 双向）。 |
| `function_reachability` | 判断一个函数能否到达另一个，并给出路径。 |

### 类型
| 工具 | 用途 |
|------|------|
| `list_types` / `get_type` | 枚举并查看本地类型。 |
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

- Server 绑定本机 HTTP 端口。请确保 :8765 和 :8766 空闲。
- 通过写操作工具所做的数据库修改保存在 IDA 数据库（`.idb`/`.i64`）中，而非原始二进制文件。
- Server 在最后一个 Worker 断连 30 秒后自动退出；再次打开 IDA 时自动重新启动。
- 修改 `ida_mcp/` 下任何文件后，需重新部署并重启 IDA，新代码才会生效。
