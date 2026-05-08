"""
recontk.modules
~~~~~~~~~~~~~~~
High-level scan modules that compose multiple capabilities.

Each module exposes an async run(target, runner, logger, **kwargs) function.
Modules are stateless — all state lives in the workspace.

Modules coordinate multi-step workflows:
  1. passiverecon: WHOIS, OSINT, passive DNS
  2. activerecon: Active DNS enumeration, TLS inspection
  3. subdomainenum: Multi-provider subdomain discovery
  4. portdiscovery: Port scanning + service detection
  5. webinspect: HTTP probing, fingerprinting, screenshot
  6. contentdiscovery: Directory/file brute-force
  7. vulnchecks: Nuclei vulnerability scanning
  8. osint: URL harvesting from archives
"""
