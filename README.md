# vortex-ids
Vortex is a near real time IDS and network surveillance engine for TCP stream data. Vortex decouples packet capture, stream reassembly, and real time constraints from analysis. Vortex is used to provide TCP stream data to a separate analyzer program.

vortex-ids is comprised of vortex, the core utility, and includes some additional utilites to enhance both its functionality, and its ability to integrate with outside analyzers.

## libBSF
libBSF is a stream filtering library based on BPF and tcpdump syntax that vortex can use. 
libBSF is an optional component of vortex, however it is included by default in the vortex spec file.

## xpipes
xpipes is a simple utility for multiplexing pipes that is similar to parallel and xargs but designed to work in situations where items are multiplexed to long running programs reading from STDIN.
xpipes is intended to be used in conjunction with vortex to create multi-threaded analyzers, but it can also be used as a standalone utility.
