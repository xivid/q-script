build/bzImage.x86_64.xz: build/bzImage.x86_64
	xz $<

build/bzImage.x86_64:
	if ! test -d build/linux/.git; then \
		git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git -b linux-rolling-lts build/linux --depth 1; \
	fi
	cd build/linux && $(MAKE) defconfig && $(MAKE) kvm_guest.config && $(MAKE) bzImage
	cp build/linux/arch/x86/boot/bzImage $@
