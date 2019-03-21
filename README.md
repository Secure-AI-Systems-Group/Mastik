# Mastik: : A Micro-Architectural Side-Channel Toolkit

## About

Micro-architectural side-channel attacks exploit contention on internal components
of the processor to leak information between processes. 
While in theory such attacks are straightforward, 
practical implementations tend to be finicky and 
require significant understanding of poorly documented processor features 
and other domain-specific arcane knowledge. 
Consequently, there is a barrier to entry into work on 
micro-architectural side-channel attacks, 
which hinders the development of the area and the analysis of the 
resilience of existing software against such attacks.

This repository contains Mastik, a toolkit for experimenting with micro-architectural side-channel attacks. Mastik aims to provide implementations of published attack and analysis techniques. 
Currently, Mastik supports six side-channel attack techniques on the Intel x86-64 architecture:

- Prime+Probe on the L1 data cache
- Prime+Probe on the L1 instruction cache
- Prime+Probe on the Last Level Cache
- Flush+Reload
- Flush+Flush
- Performance-degradation attack


## Usage

For example of usage look at the demo folder.

Additionally go to the Mastik homepage for documentation.

## Links

The Mastik Home page can be found [HERE](http://cs.adelaide.edu.au/~yval/Mastik/).
