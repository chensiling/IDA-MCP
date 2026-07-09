# IDA-MCP

一个进程内运行的 [Model Context Protocol](https://modelcontextprotocol.io)（MCP）
服务器，通过 HTTP 将 IDA Pro 的静态逆向能力暴露给兼容 MCP 的 AI 客户端。

服务器以插件形式**运行在 IDA 内嵌的 Python 解释器中**。当 IDA 加载二进制文件后，
插件启动一个 HTTP MCP 端点；任意 MCP 客户端即可连接并驱动分析——反编译、交叉引用、
类型重建、打补丁、调用图遍历等——全部通过一套稳定的、面向 LLM 的工具接口完成。

---

## 特性

- **单进程。** MCP 服务器在 IDA 自带的 Python 中执行。无外部桥接进程、无跨进程
  序列化、无 TCP 隧道。
- **客户端无关。** 通过标准 MCP over streamable HTTP 通信。任何兼容的 MCP 客户端
  均可使用；客户端只负责连接，从不启动服务器。
- **分层设计。** 薄薄的原子层封装 IDA API；组合层把原子装配成面向 LLM 认知任务、
  体积可控的工具。
- **LLM 友好的数据契约。** 所有整数以字符串形式返回（地址用十六进制，其余用十进制），
  彻底消除 64 位整数精度丢失，也免去模型做任何进制换算。
- **意图工具。** 在"一次调用对应一个 IDA 动作"的能力工具之外，更高层的意图工具能
  在单次调用中聚合完成一个推理任务所需的全部信息。

---

## 架构

```
┌────────────┐   MCP over HTTP    ┌────────────────────────────────────┐
│  MCP 客户端 │ ◄────────────────► │            IDA Pro（单进程）         │
│ (AI agent) │  streamable-http   │  ┌──────────────────────────────┐  │
└────────────┘                    │  │ MCP 服务器 (FastMCP)          │  │
                                  │  │  后台线程，ASGI/HTTP          │  │
                                  │  ├──────────────────────────────┤  │
                                  │  │ 工具 → execute_sync → IDA API │  │
                                  │  └──────────────────────────────┘  │
                                  │        IDA 内嵌 Python              │
                                  └────────────────────────────────────┘
```

进程内的三个职责层：

| 层 | 模块 | 职责 |
|----|------|------|
| **工具层** | `ida_mcp/tools/` | 语义组合；一个工具对应一个稳定的 LLM 认知动作。唯一允许组合原子的层。按功能域拆分为多个子模块，意图工具独立于能力工具。 |
| **原子层** | `ida_mcp/ida_api/` | 对 IDA API 的薄封装，单一职责。通过 `execute_sync` 封送到 IDA 主线程执行，不做组合。按功能域拆分为多个子模块。 |
| **IDA API** | IDAPython | 由 IDA Pro 提供，不修改。 |

由于绝大多数 IDA API 必须在 UI 线程调用，而 HTTP 处理运行在后台线程，每个原子都通过
`run_in_main()`（`idaapi.execute_sync`）封送到主线程。

---

## 项目结构

按功能域分层拆分，单文件保持在可维护规模；同名功能域在原子层与工具层一一对应。

```
ida_mcp.py                插件入口（PLUGIN_ENTRY）；后台线程启动 HTTP MCP 服务器。
ida_mcp/                  实现包
├── __init__.py
├── server.py            服务器入口：导入 _base 与 tools 触发工具注册，暴露 mcp。
├── _base.py             共享基础：mcp 实例、常量、错误翻译、地址/数字转换、共享辅助。
├── categories.py        确定性的导入分类表。
├── ida_api/             原子层（Layer 2），按功能域拆分
│   ├── __init__.py      汇出全部原子（对外接口与拆分前一致，api.xxx() 调用不变）。
│   ├── core.py          run_in_main、IDAError、共享 IDA 模块导入、常量。
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
└── tools/               工具层（Layer 3），按功能域拆分
    ├── __init__.py      导入各域子模块以触发 @mcp.tool 注册。
    ├── overview.py      check_connection / binary_overview / binary_info。
    ├── functions.py     analyze_function / decompile / stack_frame / switch 等。
    ├── search.py        search / trace_data / cross_references。
    ├── graph.py         call_graph / function_reachability。
    ├── types.py         类型系统工具。
    ├── lvars.py         局部变量工具。
    ├── annotate.py      rename / comment / patch / make_* / undefine。
    └── intent.py        意图工具（explore_function/explore_data/survey_capabilities/review_string_usage）。
```

> **意图工具独立**：`tools/intent.py` 与按域划分的能力工具物理分离，直观体现"能力
> 工具 vs 意图工具"的架构区分（见"工具"一节）。
>
> **依赖单向**：`tools/*` → `_base` → `ida_api`，工具子模块之间互不依赖，便于独立维护。

---

## 前置条件

- IDA Pro 9.0 或更新版本（使用现代 `tinfo_t` 类型系统与 MCP SDK 的 streamable-http
  传输）。
- Hex-Rays 反编译器（反编译相关工具依赖它）。
- 在 **IDA 内嵌的解释器**中安装 **MCP Python SDK**（会一并带入 FastMCP、Uvicorn、
  Starlette）。

> 服务器运行在 IDA 的*内嵌*解释器中，它可能与系统 `PATH` 上的任何 Python 不同。
> 请从 IDA 的 Output 窗口确认正确的解释器：
>
> ```python
> import sys; print(sys.executable)
> ```
>
> 然后把 SDK 装到该解释器：
>
> ```
> <ida-内嵌-python> -m pip install mcp
> ```

---

## 安装

将 `ida_mcp.py` **和** `ida_mcp/` 包一起复制到 IDA 的 `plugins` 目录。复制整个包目录
即可（其内部子目录结构见"项目结构"一节），最终顶层布局为：

```
<IDA plugins 目录>/
├── ida_mcp.py
└── ida_mcp/          （完整包，含 ida_api/ 与 tools/ 子包）
```

`plugins` 目录的具体位置取决于你的 IDA 安装与操作系统，请参阅 IDA 官方文档。文件与包
必须并排放置。

---

## 使用

1. 启动 IDA Pro，打开（或创建）目标二进制的数据库，等待自动分析完成。
2. 插件自动加载并启动服务器。Output 窗口会出现类似输出：

   ```
   [ida-mcp] MCP server starting on http://127.0.0.1:8765/mcp
   ```

3. 将任意 MCP 客户端指向该端点 URL。MCP 客户端配置中一个典型的远程服务器条目形如：

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

   具体配置格式取决于你的客户端，请查阅其文档了解如何注册远程 MCP 服务器。

4. 连接成功后，客户端的模型即可调用下文列出的工具。

> **修改后重新加载。** 插件在 IDA 启动时加载。修改 `ida_mcp/` 下的任何文件后，需重新
> 部署并重启 IDA，新代码才会生效。

---

## 配置

监听主机与端口定义在 `ida_mcp/_base.py`：

```python
HTTP_HOST = "127.0.0.1"
HTTP_PORT = 8765
```

若修改端口，请同步更新 MCP 客户端中配置的 URL 并重启 IDA。绑定到 `127.0.0.1` 可将端点
限制在本机访问。

---

## 数据契约

其设计使模型无需做进制换算，也不必担心整数精度：

- **所有整数以字符串返回。** 地址为十六进制（`"0x401000"`）；其余数值为十进制
  （`"2149"`）。转换在服务器出口统一完成。
- **入参接受字符串。** 地址/标识符参数接受符号名、十六进制字符串或十进制字符串，由
  服务器负责解析。
- **字节为十六进制字符串**（例如 `"90909090"`）。
- 修改数据库的写操作（重命名、打补丁、改类型、加注释、定义/取消定义）会在可能的情况下
  校验其效果，且**从不改动原始输入文件**。

---

## 工具

工具分为两类，二者都能被 MCP 客户端直接调用，区别在于**抽象层级**：

- **能力工具（capability tools）** —— 一个工具对应**一个 IDA 动作**（如反编译一个函数、
  读一个跳转表、改一个名）。粒度细、可精确控制，适合模型已明确知道下一步要做什么时使用。
- **意图工具（intent tools）** —— 一个工具对应**一个推理任务**，内部编排多个动作并把结果
  聚合成一份完备证据，替模型省去多轮往返与手工关联。适合模型面对开放式问题（"这个函数
  在做什么""这个程序有哪些能力"）时作为入口。

> 下表中标注 **【意图】** 的为意图工具，其余均为能力工具。两类工具互补：意图工具给出全局
> 判断所需的材料，能力工具用于在此基础上做精细操作或补充查询。

### 意图工具（一次调用聚合完备证据）
| 工具 | 用途 | 内部聚合 |
|------|------|---------|
| `explore_function` | **【意图】** 回答"这个函数在做什么" | 伪代码 + 被调/调用者 + 引用字符串 + 结构特征 + 确定性分类提示 |
| `explore_data` | **【意图】** 回答"这个数据/全局变量是什么、如何被使用" | 类型 + 字节/字符串值 + 所属段 + 读者/写者/取址者分类 |
| `survey_capabilities` | **【意图】** 回答"这个程序有哪些能力、分布在哪" | 按能力面分桶的导入 + 每个导入的调用者函数 |
| `review_string_usage` | **【意图】** 回答"某字符串在哪里、如何被使用" | 匹配字符串 + 引用函数 + 首个引用函数的伪代码片段 |

### 概览与导航
| 工具 | 用途 |
|------|------|
| `check_connection` | 确认服务器可响应且已加载数据库。 |
| `binary_overview` | 入口点、按类别分桶的导入、特征字符串、段布局。 |
| `binary_info` | 文件格式、处理器、位数、字节序、image base、地址范围。 |

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

- 服务器绑定本机 HTTP 端口。请确保该端口空闲，且客户端能在同一台机器上访问。
- 通过写操作工具所做的数据库修改保存在 IDA 数据库（`.idb`/`.i64`）中，而非原始二进制
  文件。
- 重量级操作（例如反编译超大函数）在 IDA 主线程同步执行，中途无法中断。
