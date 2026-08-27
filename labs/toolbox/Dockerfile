# Software Security — lab toolbox (Docker-first; replaces the full Kali VM)
#
# A small Linux container with the dev/attacker tools that don't run cleanly on a
# Windows/macOS host: clang + libFuzzer + ASan, gdb, and recon tools. Used mainly
# in Week 11 (memory-safety exploitation) and for optional recon in Weeks 4/10.
#
# Build:
#   docker build -t softsec-toolbox labs/toolbox
# Run (ptrace caps + relaxed seccomp so gdb/ASan work; mount your lab dir):
#   docker run -it --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
#       -v "$PWD":/work -w /work softsec-toolbox
#
# silkeh/clang ships a working libFuzzer runtime (Apple clang does not), so
# `clang -fsanitize=address,fuzzer harness.c -o fuzz && ./fuzz` works here.
FROM silkeh/clang:19-bullseye

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make \
        gdb \
        python3 python3-pip \
        nmap sqlmap \
        curl git vim less ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
CMD ["/bin/bash"]
