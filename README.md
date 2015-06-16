# vortex-ids
Vortex is a near real time IDS and network surveillance engine for TCP stream data. Vortex decouples packet capture, stream reassembly, and real time constraints from analysis. Vortex is used to provide TCP stream data to a separate analyzer program.

Vortex is the core utility and the vortex downloads also include related stuff like the xpipes program. libBSF is a stream filtering library that vortex can use. If you download RPMs for vortex, you'll need to download libBSF also. If you download the tarball, libBSF is optional but recommended.