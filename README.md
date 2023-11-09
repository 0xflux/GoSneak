# GoSneak

The ninja of process injection! Silently slipping into processes with the stealth and precision of a Golang-coded shadow. Shh, it's so sneaky, even the bytes don't hear it coming!

A small snippet from my private Go based software and server control framework, showcasing some simple process injection written in Go and C. This is purely PROOF OF CONCEPT and simply injects a DLL into a process for it to be run. This is in NO WAY to be used for malicious purposes and I DO NOT ENDORSE this code being used for malicious purposes. 

The injector is mostly in C, wrapped in some Go for fun, showing cross compatability of classical C development with a higher level language such as Go. I have found there are actual benefits to doing this in respect of anti-detection; something I may blog about in the future!
