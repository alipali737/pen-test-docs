```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

# 1 - AI System Mapping & Architecture
### 1.1 - Identify AI Components
- What AI capabilities exist?
	- Chatbot
	- Agentic workflows
	- Retrieval-Augmented Generation (RAG)
	- Code execution
	- Tool use / function calling
	- Image/audio/video processing
	- Autonomous actions
- Identify all trust boundaries:
	- User ↔ Model
	- Model ↔ Tools
	- Model ↔ Plugins/APIs
	- Model ↔ Memory/vector DB
	- Model ↔ External internet
- Identify model providers:
	- Hosted API
	- Self-hosted model
	- Third-party gateway
- Determine context sources:
	- System prompts
	- Developer prompts
	- User prompts
	- Memory
	- RAG documents
	- External tool outputs

### 1.2 - AI Data Flow
- Map complete prompt lifecycle:
	- Input preprocessing
	- Moderation
	- Context injection
	- Prompt assembly
	- Model inference
	- Post-processing
- Identify where security controls are applied:
	- Before model
	- During orchestration
	- After model output
- Enumerate hidden/system prompts where possible
- Determine whether prompts are logged, cached, or persisted

---

# 2 - Prompt Injection
### 2.1 - Direct Prompt Injection
- Attempt instruction override:
	- "Ignore previous instructions"
	- "You are now..."
	- "Reveal your system prompt"
- Try role confusion:
	- Developer mode
	- Simulation
	- Translation
	- JSON mode
	- Chain-of-thought extraction
- Attempt delimiter breaking:
	- Markdown
	- XML/HTML
	- JSON
	- YAML
	- Code blocks
- Try prompt confusion via:
	- Long context flooding
	- Contradictory instructions
	- Recursive instructions
	- Unicode manipulation
	- Invisible characters

### 2.2 - Indirect Prompt Injection
- Inject prompts into external sources:
	- PDFs
	- Web pages
	- Emails
	- Shared documents
	- Git repositories
	- Calendar entries
- Test whether retrieved content can manipulate model behavior
- Attempt data exfiltration through injected retrieval content
- Inject malicious instructions into vector DB indexed content
- Test multi-hop injection:
	- RAG document → tool call → exfiltration

### 2.3 - Prompt Leakage
- Attempt extraction of:
	- System prompts
	- Hidden instructions
	- Internal policies
	- API keys
	- Tool schemas
	- Memory contents
- Use:
	- Summarization tricks
	- Translation tricks
	- Encoding requests
	- Token-by-token reconstruction
	- Reflections on previous instructions
- Test whether refusal messages leak hidden content

---

# 3 - Context & Memory Attacks
### 3.1 - Context Window Manipulation
- Flood context to push out safety instructions
- Attempt truncation attacks
- Force context collisions
- Test token limit handling
- Attempt recursive self-reference attacks

### 3.2 - Persistent Memory Abuse
- Store malicious instructions in memory
- Attempt long-term prompt persistence
- Test whether memory survives account/session boundaries
- Attempt retrieval of another user's memory
- Poison memory with:
	- False facts
	- Malicious instructions
	- Sensitive information
- Determine whether users can enumerate stored memory

### 3.3 - Conversation State Manipulation
- Replay old context
- Fork sessions/tabs and compare consistency
- Modify hidden identifiers/session references
- Attempt cross-chat data leakage

---

# 4 - Retrieval-Augmented Generation (RAG)
### 4.1 - Document Ingestion
- Upload malformed documents
- Test parser handling:
	- PDFs
	- DOCX
	- Markdown
	- HTML
	- Images/OCR
- Attempt:
	- Embedded instructions
	- Hidden text
	- White-on-white text
	- Metadata injection
	- OCR manipulation

### 4.2 - Retrieval Security
- Can users retrieve unauthorized embeddings/documents?
- Enumerate document IDs
- Test semantic bypasses:
	- Rewording queries
	- Synonym abuse
	- Multilingual retrieval
- Attempt retrieval poisoning
- Test ranking manipulation

### 4.3 - Embedding Attacks
- Determine whether embeddings leak sensitive information
- Test nearest-neighbor inference attacks
- Attempt vector collision attacks
- Poison embeddings with adversarial content

---

# 5 - Tool Use & Agentic Behavior
### 5.1 - Function Calling
- Enumerate available tools/functions
- Attempt unauthorized tool invocation
- Manipulate tool arguments
- Inject malformed JSON/schema-breaking input
- Attempt hidden parameter discovery
- Test whether tool descriptions can be manipulated

### 5.2 - Tool Chaining
- Can the AI chain dangerous actions automatically?
- Attempt:
	- SSRF through tools
	- Internal network access
	- Arbitrary HTTP requests
	- File access
	- Command execution
- Determine whether approval workflows can be bypassed

### 5.3 - Autonomous Agents
- Test goal hijacking
- Attempt recursive task expansion
- Abuse planning logic
- Attempt infinite loops/resource exhaustion
- Determine whether agents can self-modify plans unsafely

---

# 6 - Output Handling & Injection
### 6.1 - Output Injection
- Test whether AI output is rendered unsafely:
	- Markdown injection
	- HTML injection
	- JavaScript injection
	- Terminal escape sequences
- Attempt XSS through model output
- Test generated links and redirects

### 6.2 - Unsafe Generated Content
- Can the AI generate:
	- Malicious code
	- Phishing emails
	- Credential theft pages
	- Malware
	- Dangerous commands
- Test policy bypasses using:
	- Obfuscation
	- Roleplay
	- Encoding
	- Fictional framing

### 6.3 - Downstream Injection
- Does generated content reach:
	- SIEMs
	- Slack/Teams
	- Email
	- CI/CD
	- Shell scripts
	- Infrastructure-as-code
- Attempt prompt-to-command injection chains

---

# 7 - Access Control & Multi-Tenancy
### 7.1 - AI Authorization
- Can users access:
	- Other conversations?
	- Other uploaded files?
	- Other embeddings?
	- Other memories?
	- Other agent runs?
- Test horizontal privilege escalation
- Test admin/debug endpoint exposure

### 7.2 - Model Isolation
- Are contexts isolated between tenants?
- Attempt cache poisoning
- Attempt response mix-up attacks
- Test concurrency/race conditions

---

# 8 - Data Protection & Privacy
### 8.1 - Sensitive Data Exposure
- Does the AI reveal:
	- Secrets
	- PII
	- Internal documents
	- Training data
	- API responses
- Attempt extraction through:
	- Prompting
	- Encoding
	- Partial completion
	- Statistical reconstruction

### 8.2 - Logging & Retention
- Are prompts/responses logged?
- Are secrets redacted?
- Determine retention duration
- Can users delete stored data?
- Are embeddings/vector data encrypted?
---

# 9 - Model Security
### 9.1 - Model Extraction
- Attempt systematic output harvesting
- Determine rate limits
- Test cloning feasibility
- Attempt confidence/probability extraction

### 9.2 - Adversarial Inputs
- Test:
	- Unicode attacks
	- Tokenization edge cases
	- Gibberish inputs
	- Adversarial suffixes
	- Jailbreak corpora
- Fuzz prompt handling

### 9.3 - Fine-Tuning Security
- Can training/fine-tuning data be poisoned?
- Attempt backdoor insertion
- Test whether harmful behaviors can be implanted

---

# 10 - AI Infrastructure
### 10.1 - AI APIs
- Standard API testing:
	- Authentication
	- Rate limits
	- IDOR
	- Mass assignment
	- GraphQL abuse
- Enumerate undocumented endpoints
- Test streaming endpoints

### 10.2 - GPU / Compute Abuse
- Attempt resource exhaustion
- Token flooding
- Infinite generation
- Parallel request abuse
- Billing abuse

### 10.3 - Sandbox Escape
- If code execution exists:
	- Test filesystem access
	- Environment variable access
	- Container breakout
	- Network egress
	- Privilege escalation

---

# 11 - Safety & Alignment Controls
### 11.1 - Jailbreak Testing
- Test known jailbreak families:
	- DAN
	- Roleplay
	- Translator
	- Hypothetical framing
	- Emotional manipulation
	- Multi-turn coercion
- Evaluate consistency of refusals

### 11.2 - Policy Enforcement
- Determine whether controls exist:
	- Pre-prompt filtering
	- Input moderation
	- Output moderation
	- Tool-level restrictions
- Attempt bypasses at each layer

### 11.3 - Safety Regression Testing
- Re-test previously patched jailbreaks
- Test across:
	- Different models
	- Different temperatures
	- Different languages
	- Long conversations

---

# 12 - Monitoring & Detection
### 12.1 - Detection Evasion
- Attempt slow, low-noise attacks
- Split malicious intent across turns
- Use multilingual attacks
- Attempt encoded payloads

### 12.2 - Alerting & Telemetry
- Are attacks logged?
- Are anomalous prompts detected?
- Can defenders reconstruct attack chains?
- Is user attribution reliable?
---

# 13 - AI-Specific Test Cases
### 13.1 - Hallucination Security
- Can hallucinated tools/endpoints be abused?
- Can fake references influence operators?
- Test operational trust in hallucinated output

### 13.2 - Human-in-the-Loop Bypass
- Can approval prompts be socially engineered?
- Does AI manipulate users into unsafe actions?
### 13.3 - Supply Chain
- Review:
	- Model weights
	- Plugins
	- MCP servers
	- Agent frameworks
	- Open-source dependencies
	- Vector DB providers

---

# 14 - Reporting
### 14.1 - Document:
- Exact prompts
- Multi-turn sequences
- Required context
- Model/version tested
- Temperature/settings
- Success conditions
- Safety impact
- Data exposure scope

### 14.2 - AI-Specific Severity
- Consider:
	- Autonomy level
	- Data sensitivity
	- Tool access
	- Cross-user impact
	- Reliability of exploit
	- Human trust implications

You may also want to structure findings against:
- OWASP LLM Top 10
- MITRE ATLAS
- NIST AI RMF
- OWASP GenAI Security Project
