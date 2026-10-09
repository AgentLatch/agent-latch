# Challenge: AI Agent Code Generator — Path Traversal in File Tool (Challenge 02)

## 1. Upstream Source Repository
* **GitHub Link:** https://github.com/techwithtim/AI-Agent-Code-Generator
* **Target Vulnerable File:** code_reader.py (Lines 5–9)

## 2. What is the Vulnerability?
* The `code_reader` tool builds a path with `os.path.join("data", file_name)` and
  opens it without verifying the result stays inside the `data` directory. A user can
  therefore ask the agent to read a relative path such as `../.env`, escaping the
  intended folder and leaking arbitrary files from the host to the caller.

## 3. Explain It Like I'm New
* Picture a library where you're only allowed into one room. You hand the librarian a
  slip with a book's name, and they fetch it. But the slip can also say "go next door,
  up the stairs, into the locked office" — and the librarian follows it literally,
  because they only ever check the book name, never whether you're allowed in that
  room. Here `../` is that "go next door" instruction: the tool meant to read files in
  one folder can be walked out of it to grab any file on the machine.
