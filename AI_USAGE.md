# AI usage: dsc26-cyb-w03

Keep the three headings below exactly as they are. The grader stops and scores 0 if this file is
missing or any of the three headings is missing. It does not score what you write; your Track
Mentor reads it, and the W8 defence can ask about it.

## Tools

Claude (Anthropic's chat assistant) for:
- **Understanding the task:** it explained the README and gave me a general plan for the task

## What AI got wrong

it gave a setup command that failed. The instructions told me to run conda deactivate and then uv venv. But uv was installed in your conda base environment, so uv disappeared after the deactivate. i noticed by running it (“uv not found”), and the fix was to run conda activate base first (or install uv separately) and build the venv from there

## In my own words

<!-- One or two sentences each, written without AI. -->

1. Why does `get_document` return 404 rather than 403 when a client asks for another client's contract?
returning a 404 Not Found helps prevent information leakage and enumeration attacks. when an API returns a 403 it tells an unauthorized user that the resource does exist but they are not allowed to access it. this can give away clues about the system. 404 Not Found makes the resource seem like it doesn't exist at all. this keeps things ambiguous and makes it harder for attackers to guess which IDs are valid

2. Why must `verify_password` refuse a stored hash that is shorter than 32 bytes, even though the prefix matches?
it makes sure the cryptographic integrity stays strong and enforces the derived key length (dklen=32) as set by the scrypt parameters. if a shorter or truncated hash is accepted it reduces the needed entropy, which leads to length mismatches or out-of-bound issues when doing comparison checks