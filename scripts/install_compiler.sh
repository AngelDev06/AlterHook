#!/usr/bin/bash

declare -A compiler
compiler_name=$1
target_arch=$2

if [[ "$compiler_name" == "clang" ]]; then
  wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | sudo tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc
  sudo add-apt-repository "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy main"
  sudo apt update > /dev/null
  sudo apt install clang-19 lld-19 libc++-19-dev libc++abi-19-dev > /dev/null
  compiler=([bin,C]=clang [bin,C++]=clang++ [version]=19)
elif [[ "$compiler_name" == "gcc" ]]; then
  sudo apt install gcc-12 g++-12 > /dev/null
  compiler=([bin,C]=gcc [bin,C++]=g++ [version]=12)
else
  echo "[X] Invalid compiler, select one of (clang, gcc)" >&2
  return 1
fi

for bin in {${compiler[bin,C]},${compiler[bin,C++]}}; do
  old="$(which $bin)"
  new="$(which ${bin}-${compiler[version]})"
  sudo update-alternatives --install "$old" $bin "$new" 100
  sudo update-alternatives --set $bin "$new"
done

if [[ "$target_arch" != "x64" ]]; then
  sudo apt install gcc-12-multilib g++-12-multilib > /dev/null
fi
