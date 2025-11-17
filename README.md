# SemRay - AI-Powered Semantic Analysis for IDA Pro

SemRay is a powerful IDA Pro plugin that leverages Google's Gemini AI to provide intelligent semantic analysis of binary code. It automatically suggests meaningful function names, detailed comments, and descriptive variable renames based on deep contextual understanding of your code.

## Features

- **Intelligent Function Naming**: Generate concise, descriptive function names that encode role and domain (e.g., `crc32_checksum`, `parse_http_header`)
- **Comprehensive Comments**: Automatically create detailed multi-line comments explaining function behavior
- **Variable Renaming**: Suggest meaningful names for local variables and function arguments
- **Context-Aware Analysis**: Analyzes callers, callees, and cross-references to understand function relationships
- **Flexible Analysis Modes**:
  - Analyze single functions
  - Analyze all functions in context
  - Analyze functions within N levels of call depth
- **Multiple Content Modes**: Choose between decompiled C code or raw assembly for LLM analysis
- **Optional CodeDumper Integration**: Enhanced context discovery with virtual calls, jump tables, and PTN provenance annotations
- **Interactive UI**: Review and selectively apply suggested changes through an intuitive tabbed interface

## Requirements

### Essential

- **IDA Pro 7.6+** with Python 3 and PyQt5 support
- **Hex-Rays Decompiler** (for decompilation mode and PTN analysis)
- **Python Libraries**:
  ```bash
  pip install google-genai pydantic
  ```
- **Google AI API Key**: Required for Gemini API access

## Installation

### 1. Plugin Installation

Copy the plugin directory to your IDA plugins folder:

```bash
# Linux
cp -r semray ~/.idapro/plugins/semray

# Windows
copy semray "C:\Users\YourName\AppData\Roaming\Hex-Rays\IDA Pro\plugins\semray"

# macOS
cp -r semray ~/Library/Application\ Support/Hex-Rays/IDA\ Pro/plugins/semray
```

Alternatively, you can place it directly in the IDA installation's plugins directory:

```bash
# Example for Linux
cp -r semray /opt/ida-pro/plugins/semray
```

### 2. Python Dependencies

Install required Python libraries in IDA's Python environment:

```bash
# If using system Python (ensure it matches IDA's Python version)
pip install google-genai pydantic

# If using IDA's bundled Python
/path/to/ida/python3 -m pip install google-genai pydantic
```

### 3. API Key Configuration

Set your Google AI API key as an environment variable:

```bash
# Linux/macOS - Add to ~/.bashrc or ~/.zshrc
export GOOGLE_API_KEY="your-api-key-here"

# Windows - Set as system environment variable
setx GOOGLE_API_KEY "your-api-key-here"
```

To obtain a Google AI API key:
1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Sign in with your Google account
3. Create a new API key
4. Copy and set it as the `GOOGLE_API_KEY` environment variable

### 4. Verify Installation

Start IDA Pro and check the output window for:
```
Initializing SemRay (Google AI Semantic Analysis) plugin.
SemRay: CodeDumper integration enabled.  # (if CodeDumper is available)
SemRay (Google AI Semantic Analysis) initialized successfully.
```

## Usage

### Quick Start

1. **Navigate to a function** in IDA Pro (Disassembly or Pseudocode view)
2. **Right-click** to open the context menu
3. Select **SemRay Analysis** from the menu
4. Choose your analysis mode:
   - **Analyze CURRENT Func Only**: Analyzes only the selected function
   - **Analyze ALL Funcs in Context**: Analyzes the function plus all callers/callees in context
   - **Analyze Current + N Levels**: Analyzes functions within N depth levels

### Configuration Prompts

When you trigger an analysis, you'll be prompted for:

1. **Content Mode**: Choose between:
   - **Decompiled**: Uses Hex-Rays decompiled C pseudocode (recommended)
   - **Assembly**: Uses raw disassembly (useful when decompilation fails)

2. **Context Depths**:
   - **Caller Depth**: How many levels of calling functions to include (default: 1)
   - **Callee Depth**: How many levels of called functions to include (default: 1)
   - **Analysis Depth**: (Depth-limited mode only) How many function levels to analyze

### Analysis Workflow

1. **Context Collection**: The plugin gathers code, call graphs, cross-references, and literals
2. **LLM Processing**: Sends the context to Google's Gemini model for semantic analysis
3. **Results Display**: Opens a tabbed UI showing suggestions for each function
4. **Review & Apply**: 
   - Review each suggestion
   - Uncheck items you don't want to apply
   - Click **Apply Selected** to update your IDB
   - Click **Close** to dismiss without changes

### Results UI

The results window displays tabs for each analyzed function, showing:

- **Suggested Function Name**: With reasoning and evidence
- **Suggested Comment**: Multi-line documentation of function behavior
- **Variable Renames**: Original → New name mappings with explanations

Each suggestion has a checkbox - uncheck to exclude it from being applied.

### Batch Analysis

You can also analyze multiple functions at once:

1. Go to **Edit → Plugins → SemRay (Google AI Semantic Analysis)**
2. Enter comma-separated function names or addresses:
   ```
   sub_401000, parse_header, 0x402340
   ```
3. Choose content mode and context depths
4. Review and apply results

## How It Works

### Context Building

SemRay builds rich context for the LLM by collecting:

1. **Code Content**:
   - Decompiled C pseudocode (via Hex-Rays)
   - Or raw disassembly with labels and addresses

2. **Call Graph**:
   - Direct calls
   - Indirect calls
   - Virtual calls (with CodeDumper)
   - Jump tables (with CodeDumper)
   - Tail calls

3. **Semantic Hints**:
   - String literals referenced in functions
   - Large constant values
   - Function prototypes/signatures

4. **PTN Annotations** (with CodeDumper):
   - Provenance tracking of data flows
   - Virtual table analysis
   - Enhanced cross-reference context

### LLM Processing

The plugin sends a carefully crafted prompt to Google's Gemini model that includes:

- **Persona**: "You are an expert reverse engineer"
- **Naming Contract**: Rules for meaningful, non-generic names
- **Call Graph**: Relationships between functions
- **Code Context**: All relevant source code
- **Schema Enforcement**: Structured JSON output via response schema

The LLM analyzes the code holistically and provides:
- Function names that encode purpose and domain
- Detailed comments explaining behavior
- Evidence-based reasoning for each suggestion
- Variable renames that clarify intent

### Name Validation

The plugin filters out generic/unhelpful names using regex patterns:
- Rejects: `var5`, `tmp`, `foo`, `bar`, `helper`, `unused`
- Only accepts: meaningful, descriptive identifiers

### IDB Updates

When you apply changes, the plugin:
1. Sets function comments (with word wrapping)
2. Renames functions (with collision checking)
3. Renames local variables (using Hex-Rays API)
4. Marks affected functions as dirty
5. Refreshes pseudocode views automatically

## Configuration

### Model Selection

By default, SemRay uses `gemini-flash-latest` for speed and cost-efficiency. To change the model, edit `semray.py`:

```python
DEFAULT_GEMINI_MODEL = "gemini-flash-latest"  # or "gemini-pro-latest"
MODELS_TO_REGISTER = [DEFAULT_GEMINI_MODEL]
```

### Default Depths

Customize default analysis depths:

```python
DEFAULT_CONTEXT_CALLER_DEPTH = 1
DEFAULT_CONTEXT_CALLEE_DEPTH = 1
DEFAULT_ANALYSIS_DEPTH = 1
```

### Cross-Reference Types

Control which reference types are considered (when using CodeDumper):

```python
DEFAULT_XREF_TYPES = {
    'direct_call',
    'indirect_call',
    'data_ref',
    'immediate_ref',
    'tail_call_push_ret',
    'virtual_call',
    'jump_table',
}
```

### Safety Settings

The plugin disables Google AI's content filtering to avoid blocking reverse engineering content. Adjust in `semray.py` if needed:

```python
DEFAULT_SAFETY_SETTINGS = [
    types.SafetySetting(category='HARM_CATEGORY_HATE_SPEECH', threshold='BLOCK_NONE'),
    types.SafetySetting(category='HARM_CATEGORY_DANGEROUS_CONTENT', threshold='BLOCK_NONE'),
    types.SafetySetting(category='HARM_CATEGORY_HARASSMENT', threshold='BLOCK_NONE'),
    types.SafetySetting(category='HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold='BLOCK_NONE'),
]
```

## CodeDumper Integration

SemRay can optionally use the CodeDumper plugin for enhanced capabilities:

### With CodeDumper

- Advanced virtual call resolution via v-table analysis
- Jump table detection and analysis
- Detailed cross-reference reasons
- PTN (Provenance Tracking Network) annotations showing data flow
- More comprehensive context discovery

### Without CodeDumper

- Falls back to standard IDA API functions
- Basic call graph analysis
- Direct and indirect call tracking
- Fully functional but with less contextual information

The plugin automatically detects CodeDumper and enables integration if available.

## Troubleshooting

### Plugin Not Loading

**Check IDA Output Window** for error messages:
- "PyQt5 not found": Install PyQt5 in IDA's Python environment
- "pydantic not found": Install pydantic (`pip install pydantic`)
- "google-genai not found": Install google-genai (`pip install google-genai`)

### API Key Issues

**"GOOGLE_API_KEY environment variable not set"**:
- Verify the environment variable is set: `echo $GOOGLE_API_KEY` (Linux/Mac) or `echo %GOOGLE_API_KEY%` (Windows)
- Restart IDA Pro after setting the variable
- Check for typos in the variable name

### Empty or Blocked Responses

**"Google AI response was empty or blocked"**:
- Check Google AI API quota/billing
- Review safety settings if content is being filtered
- Try a simpler function first to verify API connectivity

### Decompilation Failures

**"Decompilation FAILED"**:
- Ensure Hex-Rays decompiler is installed and licensed
- Try **Assembly** mode instead of **Decompiled** mode
- Some functions may not decompile due to code complexity

### Variable Rename Failures

**Variables not renamed**:
- Ensure the function can be decompiled
- Check that variable names match exactly (case-sensitive)
- Some variables may be compiler-generated and cannot be renamed

### Performance Issues

**Slow analysis**:
- Reduce caller/callee depth (try 1 or 2 instead of higher values)
- Analyze fewer functions at once
- Use "Analyze CURRENT Func Only" for individual functions
- Consider using `gemini-flash-latest` instead of `gemini-pro`

## Best Practices

1. **Start Small**: Begin with single function analysis to verify setup and understand results
2. **Iterative Refinement**: Analyze high-level functions first, then drill down into details
3. **Context Balance**: More context improves accuracy but increases cost and time
   - Depth 1-2: Fast, good for focused analysis
   - Depth 3+: Slower, better for understanding complex relationships
4. **Review Carefully**: Always review suggestions before applying - AI can make mistakes
5. **Backup Your IDB**: Keep backups before applying large batch changes
6. **Use Decompiled Mode**: Generally provides better results than assembly
7. **Check Naming Contract**: Ensure suggested names follow your team's conventions

## Architecture

### Plugin Structure

```
semray/
├── semray.py              # Main plugin file
├── ida-plugin.json        # IDA plugin metadata
└── codedump/              # Optional CodeDumper integration
    ├── codedump.py        # Context discovery utilities
    ├── micro-analyzer.py  # Micro-architectural analysis
    └── ptn_utils.py       # PTN provenance tracking
```

### Key Components

1. **Configuration** (Lines 127-173): Constants, API settings, models
2. **Data Models** (Lines 186-219): Pydantic schemas for validation
3. **Context Builder** (Lines 337-496): Gathers code, call graphs, semantics
4. **Analysis Orchestrator** (Lines 501-647): Manages the analysis pipeline
5. **UI Components** (Lines 650-908): PyQt5 widgets for results display
6. **IDA Integration** (Lines 911-1207): Actions, hooks, plugin lifecycle

### Execution Flow

```
User Action (Right-click menu)
    ↓
CtxActionHandler.activate()
    ↓
async_call() orchestrates:
    ↓
1. build_context_material() [IDA main thread]
    ↓
2. Construct LLM prompt with context
    ↓
3. do_google_ai_analysis() [Background thread]
    ↓
4. Parse & validate JSON response
    ↓
5. do_show_ui() [UI thread]
    ↓
User reviews and clicks "Apply Selected"
    ↓
_perform_ida_updates() [IDA main thread]
    ↓
IDB updated, views refreshed
```

## License

This plugin is provided as-is for reverse engineering and security research purposes.

## Contributing

Contributions are welcome! Key areas for improvement:
- Support for additional LLM providers (OpenAI, Claude, etc.)
- Enhanced prompt engineering for better results
- Additional context extraction strategies
- UI/UX improvements
- Performance optimizations

## Changelog

### Current Version
- Initial release with Google AI (Gemini) integration
- Support for decompiled and assembly analysis modes
- Optional CodeDumper integration
- Interactive UI for reviewing suggestions
- Concurrent analysis prevention
- Comprehensive error handling and fallbacks

## Support

For issues, questions, or feature requests, please check the output window in IDA Pro for diagnostic information and error messages.

## Credits

- Built on IDA Pro's powerful reverse engineering platform
- Leverages Google's Gemini AI for semantic understanding
- Integrates with CodeDumper plugin for enhanced context (optional)
- Uses Pydantic for robust data validation
