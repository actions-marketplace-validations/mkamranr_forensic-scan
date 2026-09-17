# Product Requirement Document (PRD): "Hidden Logic & Obfuscation" Forensic AST Scanner

## 1. Executive Overview

The **Hidden Logic & Obfuscation Forensic AST Scanner** (`forensic-scan`) is an advanced, language-agnostic open-source static analysis tool. Its primary mission is to detect deliberate human or machine-generated obfuscation, covert backdoors, binary payload smuggling in non-code files, and anomalous code structures designed to evade conventional security linters and automated security reviews (e.g., attacks similar to the *XZ Utils backdoor* or malicious NPM/PyPI install scripts).

Unlike traditional AST linters that match known rule signatures, this scanner measures structural anomalies, AST entropy, control-flow complexity, string dynamic evaluation, and binary asset embedding.

## 2. Core Functional Specifications & User Story

### User Story

As an open-source maintainer or security auditor, I want to run `forensic-scan ./` against inbound Pull Requests and dependencies so that I can automatically catch hidden backdoors, obfuscated payloads, macro tricks, dynamic execution traps (`eval`/`exec`/function-pointer resolution), and binary file manipulation before merging code into main branches.

### Key Capabilities

1. **AST Entropy & Complexity Analysis**: Calculate Shannon entropy and cyclomatic density across AST nodes to identify code blocks with unnaturally low or high structural entropy (hallmarks of packed/obfuscated code).

2. **Obfuscated Logic & Dynamic Traps Detection**: Flag dynamic evaluation, character code arrays, runtime string decryption (`atob`, `base64`, `zlib`, bitwise XOR loops), and hidden function pointer indirection.

3. **Steganographic Asset & Test Fixture Inspection**: Scan non-code files (e.g., test fixtures, `.png`, `.tar`, `.dat`, `.svg`) for embedded binary payloads or hidden compressed archives extracted at build/test time.

4. **Macro & Preprocessor Expansion Tracing**: Resolve C/C++ macros, build scripts (`Makefile`, `CMakeLists.txt`, `setup.py`), or dynamic JavaScript/Python imports to detect hidden execution phases during build steps.

## 3. System Architecture & Component Design

```
[ Input: Source Code & Repository Assets ]
                   │
                   ▼
[ AST & File Scanner Engine (Tree-sitter) ]
        ├── Source AST Parsing (C, C++, Py, JS/TS, Rust, Go)
        └── Non-Code File & Asset Inspector
                   │
                   ▼
[ Forensic Feature Extraction Pipeline ]
        ├── Entropy Evaluator (Shannon Entropy over Identifiers/Strings)
        ├── Dynamic Call & Reflection Engine
        ├── Binary Payload & Fixture Forensic Engine
        └── Build Script Anomaly Inspector
                   │
                   ▼
[ Forensic Scoring Engine & Heuristics Evaluator ]
                   │
                   ▼
[ Reporter & Exporter ] ──► Outputs: Markdown Forensic Report, JSON, SARIF
```

## 4. Detailed Component Requirements

### 4.1 Parser & AST Extraction Module (`src/parser/`)

* **Technology**: `tree-sitter` for source code parsing; `libmagic` / MIME-type detection for non-code files.

* **Behavior**:

  * Traverses repo files including test directories, fixtures, build files (`setup.py`, `postinstall.js`, `Makefile`).

  * Extracts AST nodes: string literals, byte arrays, function calls, variable names, macro definitions, control flow graphs.

### 4.2 Forensic Modules

#### Module A: AST Entropy & Anomaly Engine (`src/engine/entropy.py`)

* Calculates **Shannon Entropy** ($H = -\sum p_i \log_2 p_i$) over identifier names, literal strings, and AST node depth ratios.

* Flags code blocks exceeding threshold limits:

  * High String/Literal Entropy ($H > 5.2$): High probability of encrypted blobs, base64 strings, or shellcode.

  * Identifier Uniformity/Randomness ($H_{names} > 4.5$): High probability of obfuscator tools (e.g., `js-obfuscator`, `pyarmor`).

#### Module B: Dynamic Execution & Obfuscation Detector (`src/engine/obfuscation.py`)

Identifies dynamic evaluation patterns across supported languages:

* **Python**: `eval()`, `exec()`, `getattr()`, `__import__()`, `ctypes.string_at()`, `codecs.decode()`.

* **JavaScript/TypeScript**: `eval()`, `Function()`, `VM.runInContext()`, string character array join tricks (`String.fromCharCode(...)`), `Buffer.from(..., 'hex')`.

* **C/C++ / Rust / Go**: Obfuscated function pointer resolution, dynamic `dlopen`/`dlsym` calls, asm inline blocks modifying return pointers.

#### Module C: Steganographic & Binary Payload Inspector (`src/engine/binary_assets.py`)

Inspects non-code files (e.g., test files, images, sample datasets):

* Detects hidden compressed archives (`gzip`, `xz`, `bzip2`, `zip`) appended inside media or binary test fixtures.

* Scans binary assets for executable headers (`ELF`, `MZ`/PE, `Mach-O`) hidden inside mock image/text files.

* Flags files referenced in build or test scripts that undergo bitwise transformations (e.g., XOR decoding loops during unit tests).

### 4.3 Build Script & Preprocessor Inspector (`src/engine/build_inspector.py`)

* Scans `setup.py`, `postinstall.js`, `Makefile`, `CMakeLists.txt` for shell executions (`subprocess.Popen`, `child_process.exec`, `system()`).

* Flags network requests or file decompression happening during build/install phases.

## 5. Declarative Forensic Rule Schema (`.forensic-rules.yml`)

```yaml
version: "1.0"
rules:
  - id: FOR-001
    name: High Entropy String Blob with Dynamic Execution
    severity: CRITICAL
    target_languages: [python, javascript, c]
    conditions:
      - node_type: string_literal
        min_entropy: 5.2
        min_length: 64
      - data_flow:
          source: string_literal
          sink: [eval, exec, Function, dynamic_call]
    remediation: "Extracted high-entropy string payload is passed directly into a dynamic evaluation function. Inspect string content."

  - id: FOR-002
    name: Hidden Executable Header in Non-Code Asset
    severity: CRITICAL
    target_files: ["tests/**", "fixtures/**", "assets/**"]
    conditions:
      - file_type_mismatch: true # e.g., extension is .png but header is ELF or GZIP
      - contains_magic_bytes: ["7f454c46", "4d5a", "1f8b08"] # ELF, PE, GZIP
    remediation: "Test asset contains hidden executable or compressed archive headers. Verify legitimacy of fixture."

  - id: FOR-003
    name: Character Code Array Construction Loop
    severity: HIGH
    target_languages: [javascript, python]
    conditions:
      - pattern: "String.fromCharCode(...)"
      - loop_count_threshold: 10
    remediation: "String construction using character codes detected inside a loop. Indicates string obfuscation."
```

## 6. Output Reporting Specification

### 6.1 Forensic Markdown Report Output (`forensic-report.md`)

````markdown
# 🔍 Forensic AST & Obfuscation Report

**Files Analyzed:** 128 | **Anomalies Flagged:** 2 | **Forensic Risk Score:** CRITICAL (88/100)

## 🚨 Critical Forensic Findings

### Finding FOR-002: Hidden Executable Binary in Test Fixture
- **Severity**: CRITICAL
- **File**: `tests/fixtures/sample_image.png`
- **Anomaly Type**: Magic Byte Mismatch & Embedded Binary Payload
- **Details**: File extension claims PNG image, but binary signature matches an `XZ Compressed Archive` (`fd 37 7a 58 5a 00`).
- **Referenced In**: `tests/test_parser.c:82` (XOR decryption loop detected prior to execution).

```c
// Suspicious code in tests/test_parser.c:82
uint8_t buffer[2048];
FILE *f = fopen("tests/fixtures/sample_image.png", "rb");
fread(buffer, 1, 2048, f);
for(int i=0; i<2048; i++) buffer[i] ^= 0x42; // XOR decryption loop
```

---

### Finding FOR-001: High Entropy Payload in Dynamic Execution Trap
- **Severity**: HIGH
- **File**: `scripts/postinstall.js:14`
- **Anomaly Type**: High String Entropy ($H = 5.84$) + Dynamic Evaluation (`Function()`)
- **Taint Trace**:
  1. `const raw = "aW1wb3J0IG9z..."` (Entropy: 5.84, Len: 512)
  2. `const decoded = Buffer.from(raw, 'base64').toString('utf8')`
  3. `new Function(decoded)()` at line 18
- **Remediation**: Obfuscated payload executed during install phase. Remove dynamic evaluation and inspect payload.
````

---

## 7. Implementation Roadmap & Steps for Code Generator Engine

1. **Step 1**: Initialize CLI project structure using `typer` (Python) or `clap` (Rust).
2. **Step 2**: Integrate `tree-sitter` for target language AST parsing; build a utility module to calculate Shannon Entropy over AST string literals and variable names.
3. **Step 3**: Implement binary file Inspector using magic byte signatures (`python-magic` or `infer` in Rust) to scan non-code assets for header mismatches.
4. **Step 4**: Implement dynamic execution detectors (`eval`, `exec`, `Function`, `dlopen`) and construct AST data-flow links from high-entropy strings to execution sinks.
5. **Step 5**: Build the forensic scoring engine that aggregates entropy metrics, byte mismatches, and execution traps into a unified risk score.
6. **Step 6**: Implement Markdown and SARIF reporters and build a test suite containing sample obfuscated files and backdoor patterns to validate detection rates.