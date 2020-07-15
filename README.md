# ReClass.NET VMRead Plugin
DMA plugin for ReClass.NET (https://github.com/KN4CK3R/ReClass.NET). All made possible by the [VMRead KVM DMA library](https://github.com/Heep042/vmread).

## Compiling
If you don't use the following folder hierarchy you need to fix the project references.

```
..\ReClass.NET\
..\ReClass.NET\ReClass.NET\ReClass.NET.csproj
..\ReClass.NET-SamplePlugin
..\ReClass.NET-SamplePlugin\ReClass.NET SamplePlugin.sln
```

## Note
Page protections are NOT guaranteed to work and will be invalid due to a bad method of obtaining them from the VAD. (This pretty much makes the memory scanner useless)