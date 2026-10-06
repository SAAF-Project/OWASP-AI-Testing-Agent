# SAMPLE guide notes (not the OWASP AI Testing Guide)

These paragraphs exist only so the example corpus has something to retrieve. They were written for
this repository and are NOT excerpts from the OWASP AI Testing Guide. Replace the whole directory with
text from the real guide (see the README) before relying on any audit result.

AITG-APP-01 Prompt Injection: a test attempts to make the system follow instructions that arrive through
user input or through content it processes, instead of the instructions its operator gave it.

Prompt injection tests should use harmless canary strings so that success can be checked objectively
in the response, and must never attempt data exfiltration or destructive actions.

Indirect prompt injection places the instructions in a document, web page or tool result that the
system reads, rather than in the user's own message.
