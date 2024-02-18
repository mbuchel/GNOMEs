# GNOMEs

GNOMEs are responsible for controlling the ELFs and DWARFs. The real
reason for this repo is mostly because it is so annoying to maintain
binary patches and remember what each of those machine code patches
actually accomplishes. There are also issues of how to rename functions
(building bash scripts to use objcopy is something I personally want to
avoid at all costs). All of the tools which we expose in this REPO have
been in use at the company for a period of time for our own internal
development projects. Future iterations of this codebase will expose
more of the features which we have been implementing behind the scenes
on machine code modifications.

We also noticed there was very little if any explanations on how to
add injectable functions written in a higher level language into a
statically/dynamically linked binary. This can provide a mechanism
for implementing hooks in a better manner than before,
(using LD_PRELOADs) and other techniques. This is a much harder trick
that will have a nice tutorial a bit later when we get around to it.

In the meantime, this program can take a static object with a relocation
table, and swap out the symbols with a corresponding whitelist/blacklist
of locations to perform the swap on/skip.

It can also perform binary patches in assembly, and rename symbols in
programmatic manners.

# TODOs

- [ ] Remove ELFIO dependancy
  - Reason is because ELFIO is too bulky and can be better developed with
    just using the elf library in linux.
- [ ] Remove AsmJIT/AsmTK dependancy
  - Reason is because we can perform more interesting tasks if we move up
    to using a proper LLVM backend. In fact it is impossible to properly
    add additive/destructive patches using AsmJIT/AsmTK. The main reason
    here is because there is no disassembly component inside those libraries
    which is required to redefine the relative jumps which can get screwed
    up during an additive/destructive patch.
  - Right now the way to perform an additive/destructive patch, is first
    you perform a destructive patch on the entire function in place, than
    rewrite it fully in assembly with the correct patch you had in mind.
    We do perform relocations on symbols inside this patch correctly.
- [ ] Support CUDA kernel extraction from a binary.
  - This is likely gonna be the next implementation inside this project,
    as it is our bread/butter.
- [ ] Add support for compiling static object files into the executable
      after the start.
      
# NOTICE

This is all released under the MIT license, we are not responsible for
your misuse of our project.
