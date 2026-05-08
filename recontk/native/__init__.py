"""
recontk.native
~~~~~~~~~~~~~~
Pure-Python fallback backends.  No external binaries required.

Each backend exposes an async ``run(target, workspace, logger, **kwargs)``
function that returns ``NormalizedResult``.  They are invoked by the module
layer when the registry cannot find a preferred tool binary.

Available backends
------------------
  dnsresolver    dns.resolve, dns.brute          dnspython
  httpfingerprint http.probe, http.fingerprint   httpx library
  portscan       port.scan, service.detect       asyncio TCP connect
  tlsinspect     tls.inspect                     ssl + cryptography
  screenshot     screenshot                      playwright (optional dep)
"""
