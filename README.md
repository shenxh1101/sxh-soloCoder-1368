# Malware Behavior Analyzer

基于 Python 的命令行恶意软件行为分析报告生成器。

## 功能特性

- 🔬 **沙盒动态分析**: 使用 Docker 在隔离环境中运行可疑样本
- 📁 **文件系统监控**: 追踪文件创建、修改、删除操作
- 🔑 **注册表监控**: 检测注册表/配置项修改（Windows）
- 🌐 **网络监控**: 记录所有网络连接（IP、端口、时间）
- ⚙ **进程监控**: 追踪进程创建和进程树
- 🔧 **API 调用追踪**: 记录关键 API 调用序列（基于 strace）
- 🦠 **YARA 规则扫描**: 匹配已知恶意家族特征
- 🌍 **VirusTotal 集成**: 可选查询文件在线检测结果
- 📊 **结构化报告**: 生成 HTML 或 Markdown 格式报告
- 🕸 **行为关系图**: Graphviz 可视化进程树和网络连接
- ⚠ **可疑操作高亮**: 自动识别并高亮可疑行为
- 🧹 **清理功能**: 一键清理沙盒残留和临时文件

## 安装

```bash
pip install -r requirements.txt
```

### 构建 Docker 沙盒镜像（可选，用于动态分析）

```bash
docker build -t malware-sandbox:latest .
```

### 安装 Graphviz（用于生成关系图）

**Windows**:
```
winget install graphviz
```

**Linux**:
```bash
sudo apt-get install graphviz
```

**macOS**:
```bash
brew install graphviz
```

## 使用方法

### 基本分析

```bash
# 分析可疑文件（完整分析）
python main.py analyze /path/to/suspicious.exe

# 或使用模块方式
python -m malware_analyzer analyze /path/to/suspicious.exe
```

### 仅静态分析（不运行沙盒）

```bash
python main.py analyze --no-sandbox /path/to/suspicious.exe
```

### 启用 VirusTotal 查询

首先在 `config.yaml` 中配置 API Key，然后：

```bash
python main.py analyze --virustotal /path/to/suspicious.exe
```

### 指定报告格式

```bash
# HTML 报告（默认）
python main.py analyze --format html /path/to/suspicious.exe

# Markdown 报告
python main.py analyze --format markdown /path/to/suspicious.exe
```

### 自定义沙盒运行时间

```bash
python main.py analyze --runtime 60 /path/to/suspicious.exe
```

### 清理资源

```bash
# 清理所有临时文件和 Docker 容器
python main.py cleanup

# 仅清理临时文件，不动 Docker
python main.py cleanup --no-docker
```

## 配置文件

编辑 `config.yaml` 自定义工具行为：

- `sandbox.image`: Docker 镜像名称
- `sandbox.runtime`: 样本运行时间（秒）
- `sandbox.memory`: 内存限制
- `sandbox.cpu`: CPU 限制
- `yara.rules_dir`: YARA 规则目录
- `virustotal.api_key`: VirusTotal API Key
- `report.format`: 报告格式 (html/markdown)
- `report.output_dir`: 报告输出目录

## 项目结构

```
malware_analyzer/
├── __init__.py
├── __main__.py          # 模块入口
├── cli.py               # 命令行接口
├── config.py            # 配置管理
├── utils.py             # 工具函数
├── cleanup.py           # 资源清理
├── sandbox/
│   ├── __init__.py
│   ├── docker_sandbox.py  # Docker 沙盒管理
│   └── monitor.py         # 行为监控数据解析
├── scanners/
│   ├── __init__.py
│   ├── yara_scanner.py    # YARA 规则扫描
│   └── virustotal.py      # VirusTotal API 集成
└── reporting/
    ├── __init__.py
    ├── report_generator.py  # HTML/Markdown 报告生成
    └── graph_generator.py   # Graphviz 关系图生成

rules/                       # YARA 规则目录
└── default.yar

config.yaml                  # 主配置文件
Dockerfile                   # 沙盒镜像定义
requirements.txt             # Python 依赖
```

## 报告内容

生成的报告包含：

1. **风险评分**: 综合评估（0-100）和等级（CRITICAL/HIGH/MEDIUM/LOW）
2. **文件信息**: 文件名、大小、MD5/SHA1/SHA256 哈希
3. **YARA 扫描结果**: 匹配的规则、恶意家族识别
4. **VirusTotal 结果**: 多引擎检测率（可选）
5. **可疑操作**: 高亮显示的可疑行为
6. **行为关系图**: 进程树、网络连接图、完整行为图
7. **行为时间线**: 按时间排序的所有事件
8. **详细行为**:
   - 文件系统操作
   - 网络连接
   - 进程创建
   - 注册表修改
   - API 调用序列

## 安全提示

⚠ **此工具仅供安全研究和授权测试使用**

- 仅在授权环境中运行可疑样本
- 确保 Docker 网络配置正确隔离
- 定期更新 YARA 规则库
- 不要在生产环境直接运行未经验证的样本

## License

MIT License
