# GoSneak

A small snippet from my private Go based malware (for red team operations NOT criminal / malicious) and server control framework, showcasing some simple process injection written in Go and C. 

Note: The Go 'bridge' is not currently implemented, I will look to implement the Go wrapper after the C++ POC is done. To see my blog post about this: https://0xflux.gitbook.io/flux/offensive-development/dll-injection-hiding-an-elephant-in-the-closet-edr-evasion 

**Important**

This is purely PROOF OF CONCEPT and simply injects a DLL into a process for it to be run. This is in NO WAY to be used for malicious purposes and I DO NOT ENDORSE this code being used for malicious purposes. 

A screenshot from my blog, proof that we are in fact using the assembly, and not the Windows API:

![image](https://github.com/0xflux/GoSneak/assets/49762827/ead5660f-1c47-4aca-9d2e-cd59b42b7e2d)

Proof of injection:

![image](https://github.com/0xflux/GoSneak/assets/49762827/835cae74-920b-4279-bd50-0171c736cacb)

The injector is mostly in C, wrapped in some Go for fun, showing cross compatability of classical C development with a higher level language such as Go. I have found there are actual benefits to doing this in respect of anti-detection; something I may blog about in the future!
