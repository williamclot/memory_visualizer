## Project subject:

Write a tool to visualize the content of a memory dump as a PNG picture. Each pixel represents one page of physical memory, and its color represent if it is associated to the kernel, to a userspace application, or if it is not used. In this last case, maybe two different shades could be used to differentiate pages that contain only zeros from pages that contain data.
Take a couple of memory dumps (1 or 4GB) to test the tool.


## Getting the Memory Dump

The first step is to acquire the memory dump on the infected computer. We decided to try to acquire a full memory dump from a linux machine first. To do so we used the LiME tool that we cloned from a git on github: https://github.com/504ensicsLabs/LiME
The command that we used to generate a complete memory dump file is:
```
sudo insmod ./lime.ko "path=<outfile> format=<raw|padded|lime>"
```
We also did a memory dump on a windows machine with 'Magnet RAM Capture'.
As those images were too big (8Go), we also downloaded already made images from this website: https://www.memoryanalysis.net/amf

## Using Volatility

Volatility is one of the most used memory forensic analysis tool. We clone the git from https://github.com/volatilityfoundation/volatility
The main command from volatility is:
```
python vol.py -f <memory image> --profile=<profile name> <plugin>
```
Only the windows images we found were supported by volatility.
Then we used the windows memory dump and chose an already existing image from the volatility tool.

The volatility plugin we used was memmap, which shows the memory resident pages by processes.
