(use-modules (gnu packages nss))

(packages->manifest
  (append
   (list nss-certs-for-test)
   ; openssl
   (specifications->packages '("php" "sqlite"
   "strace" "gdb" "gawk" "make" "binutils" "coreutils" "sed" "make" "util-linux" "grep" "diffutils" "gcc-toolchain" "pkg-config"
   "unzip"
   "patch"
   "sqlite"
   ))))
