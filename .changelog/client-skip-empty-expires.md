---
github.com/tempoxyz/mpp-go: patch
---
Skip Payment challenges whose `expires` field is empty so the client does not pay credentials the server rejects with "missing required expires".
