```table-of-contents
title: ## Table of Contents
style: nestedList # TOC style (nestedList|nestedOrderedList|inlineFirstLevel)
minLevel: 0 # Include headings from the specified level
maxLevel: 3 # Include headings up to the specified level
includeLinks: true # Make headings clickable
debugInConsole: false # Print debug info in Obsidian console
```

## Common Findings
- Path traversals
- Priv Esc
- Overly complex code (loops, etc)
	- `High Conditional Complexity Leading to Reduced Code Comprehension`
- Use of hardcoded values / magic numbers
- Silent logic errors (eg. `long` being cast to `32-bit int`, localisation issues with text manipulation)
- Unsafe validation (sanitising inputs, size validation for memory-sensitive contexts)
- Dead code

Reference CWE dangerous software weaknesses

## Analysis Tooling

[Semgrep](https://github.com/semgrep/semgrep) : Basically a regex engine that you can write custom rules for.

### Java
> A lot of Java tools often require a built version of the application, not just the source code.

