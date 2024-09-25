#!/bin/sh

backup_vmlinuz="$(readlink /boot/vmlinuz.lts.bak)"

for i in "$@"; do
	[ -d "$i" ] || continue

	krel="${i#/lib/modules/}"

	# skip backup kernel
	[ "$backup_vmlinuz" ] && [ "vmlinuz-$krel" = "$backup_vmlinuz" ] && continue

	if [ -e "$i"/modules.order ]; then
		echo "Generate modules.* in $krel"
		/sbin/depmod $krel
	else
		#clean up on uninstall
		rm -f "$i"/modules.alias \
			"$i"/modules.builtin.alias.bin \
			"$i"/modules.dep \
			"$i"/modules.devname \
			"$i"/modules.symbols \
			"$i"/modules.alias.bin \
			"$i"/modules.builtin.bin \
			"$i"/modules.dep.bin \
			"$i"/modules.softdep \
			"$i"/modules.symbols.bin \
			"$i"/modules.weakdep
		rmdir "$i" 2>/dev/null || :
	fi
done
